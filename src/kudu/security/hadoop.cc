// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include <algorithm>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <cstring>
#include <climits> //Used for PATH_MAX
#include <glog/logging.h>
#include <krb5/krb5.h>
#include <locale>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "hadoop.h"
#include "kudu/gutil/strings/split.h"
#include "kudu/gutil/strings/strip.h"

namespace kudu {
namespace security {

//This should be the preferred way to initialize HadoopAuthToLocal
std::unique_ptr<HadoopAuthToLocal> HadoopAuthToLocal::init(const std::string& filepath, krb5_context& ctx) {
  std::unique_ptr<HadoopAuthToLocal> hadoop_auth = std::make_unique<HadoopAuthToLocal>();
  if(!hadoop_auth->setKrb5Context(ctx)){
    return nullptr;
  }
  if(!hadoop_auth->loadConf(filepath)){
    return nullptr;
  }
  return hadoop_auth;
}

//used for tests
HadoopAuthToLocal::HadoopAuthToLocal() = default;

//Private function used only for tests
void HadoopAuthToLocal::setDefaultRealm(const std::string& realm) {
  std::unique_lock<std::shared_mutex> lock(mutex_);
  defaultRealm_ = realm;
  StripWhiteSpace(&defaultRealm_);
}

std::vector<std::string> HadoopAuthToLocal::getRules() const{
  return this->coreSiteRules_;
}

bool HadoopAuthToLocal::setKrb5Context(krb5_context& ctx){
  std::unique_lock<std::shared_mutex> lock(mutex_);
  char *realm = nullptr;
  krb5_error_code err = krb5_get_default_realm(ctx, &realm);
  if(err){
    krb5_free_default_realm(ctx, realm);
    LOG(ERROR) << "Failed to get default realm from krb5 context: " << err ;
    return false;
  }
  defaultRealm_ = std::string(realm);
  StripWhiteSpace(&defaultRealm_);
  krb5_free_default_realm(ctx, realm);
  return true;
}

bool HadoopAuthToLocal::loadConf(const std::string& filepath) {
  char buffer[PATH_MAX];
  std::string canonical_path; 
  if(realpath(filepath.c_str(), buffer)){
    canonical_path = std::string(buffer);
  }
  else {
    LOG(ERROR) << "Failed to resolve real path for " << filepath << ": " << strerror(errno) ;
    return false;
  }

  const std::string ext = ".xml";
  if (canonical_path.length() < ext.length() ||
    canonical_path.compare(canonical_path.length() - ext.length(), ext.length(), ext) != 0) {
    LOG(ERROR) << "HadoopAuthToLocal configuration file must be an XML file, but got: " << canonical_path ;
    return false;
  }

  std::ifstream file_stream(canonical_path);
  if(!file_stream.is_open()) {
    LOG(ERROR) << "Failed to open HadoopAuthToLocal configuration file: " << canonical_path ;
    return false;
  }
  return setRules(file_stream);
}

bool HadoopAuthToLocal::setRules(std::istream& input) {
  std::unique_lock<std::shared_mutex> lock(mutex_);
  this->coreSiteRules_.clear();
  std::vector<std::string> rules;
  boost::property_tree::ptree tree;
  try {
    read_xml(input, tree);
  } catch (const boost::property_tree::xml_parser_error& e) {
    LOG(ERROR) << "Malformed XML when loading from core-site.xml " << e.what();
    return false;
  }

  if(tree.find("configuration") == tree.not_found()) {
    LOG(ERROR) << "No <configuration> section found in core-site.xml";
    return false;
  }
  
  for (const auto &property : tree.get_child("configuration")){
    if(property.first == "property") {
      std::string name = property.second.get<std::string>("name", "");
      if (name == "hadoop.security.auth_to_local.mechanism"){
        if(property.second.get<std::string>("value", "") == "MIT"){
          ruleMechanism_ = RuleMechanism::MIT;
        } else {
          ruleMechanism_ = RuleMechanism::HADOOP;
        }
      }
      else if (name == "hadoop.security.auth_to_local") {
        std::string value = property.second.get<std::string>("value", "");
        
        std::string::size_type pos = 0;
        while (pos < value.length() && (pos = value.find("\r\n", pos)) != std::string::npos){
          value.replace(pos, 2, "\n");
          ++pos;
        }
        rules = strings::Split(value, "\n", strings::SkipWhitespace());
        this->coreSiteRules_.reserve(rules.size());
      }
    }
  }

  for (auto &rule : rules){
    StripWhiteSpace(&rule);
    if(!rule.empty()){
      this->coreSiteRules_.push_back(rule);
    }
  }

  if (this->coreSiteRules_.size() > 0) {
    for (const auto &rule : this->coreSiteRules_) {
      std::optional<Rule> new_rule = initRule(rule);
      if (new_rule.has_value()) {
        this->rules_.push_back(new_rule.value());
      } else {
        LOG(WARNING) << "Invalid rule: " << rule ;
      }
    }
    return true;
  }
  return false;
}

std::optional<std::vector<HadoopAuthToLocal::Token>> HadoopAuthToLocal::tokenize(const std::string &fmt) {
  std::locale loc("");
  std::vector<Token> tokens;
  tokens.reserve(fmt.length());
  if (fmt.empty()) {
    LOG(ERROR) << "Empty format string provided for HadoopAuthToLocal::tokenize";
    return std::nullopt;
  }

  if (fmt == "DEFAULT"){
    return std::nullopt;
  }
  std::size_t idx = 0;
  std::size_t end = fmt.length();
  while (idx < end) {
    if(fmt[idx] == '\\' && (idx + 1) < fmt.length() && fmt[idx+1] == '$'){
      tokens.push_back(Token{.type = Token::Type::literal, .text = "$"});
      idx += 2;
    } else if (fmt[idx] == '$'){
      size_t start = idx;
      while(++idx < fmt.length() && std::isdigit(fmt[idx], loc)){}
      tokens.push_back(Token{.type = Token::Type::placeholder,
                             .text = fmt.substr(start, idx - start)});
    } else {
      size_t start = idx;
      while (idx < end &&
              (fmt[idx] != '$' || (idx + 1 >= end) ) &&
              (fmt[idx] != '\\' || (idx + 1 >= end) || fmt[idx + 1] != '$')){
        ++idx;
      }
      tokens.push_back(Token{.type = Token::Type::literal,
                             .text = fmt.substr(start, idx - start)});
    }
  }
  return tokens;
}

std::optional<std::string> HadoopAuthToLocal::format(
  const std::string& fmt, 
  const std::vector<std::string>& values) 
{
  std::locale loc("");
  std::string result;
  std::vector<Token> tokens = tokenize(fmt).value_or(std::vector<Token>{});
  for (const auto &token : tokens) {
    if (token.type == Token::Type::placeholder) {
      size_t idx = 0;
      size_t pos = 1;
      while (pos < token.text.length() && std::isdigit(token.text[pos], loc)) {
        idx = idx * 10 + (token.text[pos] - '0');
        ++pos;
      }
      if (idx < values.size()) {
        result += values[idx];
      } else {
        LOG(WARNING) << "Placeholder " << token.text << " refers to index " << idx
                   << ", but only " << values.size() << " values provided.";
        return std::nullopt;
      }
    } else if (token.type == Token::Type::literal) {
      result.append(token.text);
    }
  }
  return result;
}

std::string HadoopAuthToLocal::escapeJavaRegexLiteral(std::string_view input) {
  static const std::string metachars = R"(.^$|()[]\{}*+?)";
  std::string output;
  //Worst case scenario where we need to escape every character
  output.reserve(input.size() * 2); 

  for (char current_char : input) {
    if (metachars.find(current_char) != std::string::npos) {
      output.push_back('\\');
    }
    output.push_back(current_char);
  }
  return output;
}

std::optional<std::string> HadoopAuthToLocal::processJavaRegexLiterals(std::string_view input) {
  std::string output;
    
  for (size_t idx = 0; idx < input.size();) {
    if (input.substr(idx, 2) == "\\Q") {
      idx += 2;
      size_t end = input.find("\\E", idx);
      if (end == std::string::npos) {
        LOG(ERROR) << "Unterminated \\Q in regex literal " << input ;
        return std::nullopt;
      } 
      output += escapeJavaRegexLiteral(input.substr(idx , end - idx));
      idx = end + 2;
    } else {
      output += input[idx];
      ++idx;
      }
  }
  return output;
}

std::optional<HadoopAuthToLocal::SedRule> HadoopAuthToLocal::parseSedRule(std::string_view sed_rule){
  std::locale loc("");
  if (sed_rule.empty()) {  
    return std::nullopt;
  }
  if (sed_rule.size() < 3 || sed_rule[0] != 's') {
    LOG(ERROR) << "Rule must start with 's' and a delimiter";
    LOG(ERROR) << "It is: '" << sed_rule << "'";
    return std::nullopt;
  }
  const char delimiter = sed_rule[1];
  //Absolute max size of any part of a sed rule
  constexpr size_t max_size = 128;
 //skip the s + delimiter
  std::string_view rule = sed_rule.substr(2);
  size_t pos = 0; 
  std::string part[2];
  int part_idx = 0;
  bool escape = false;
  std::regex match_regex;
    
  if (
    std::isalnum(delimiter, loc) || 
    std::isspace(delimiter, loc) ||  
    delimiter == '\\' || 
    delimiter == '@') 
  {
    LOG(ERROR) << "Invalid delimiter in sed rule: '" << delimiter << "'";
    return std::nullopt;
  }

  while (pos < rule.size() && part_idx < 2) {
    if(part[part_idx].size() >= max_size) {
      LOG(ERROR) << "Part " << part_idx + 1 << "of sed rule " << sed_rule << " is too long: " << 
        rule.size() << " characters. Max " << max_size;
      return std::nullopt;
    }
    char current_char = rule[pos];
    if (escape) {
      part[part_idx] += current_char;
      escape = false;
    } else if (current_char == '\\') {
      part[part_idx] += current_char;
      escape = true;
    } else if (current_char == delimiter) {
      if(++part_idx > 2){
        LOG(ERROR) << "Sed rule has too many parts: " << sed_rule ;
        return std::nullopt;
      }
    } else {
      part[part_idx] += current_char;
    }
    ++pos;
  }

  if (part_idx != 2 ) {
    LOG(ERROR) << "Malformed sed rule: " << sed_rule ;
    return std::nullopt;
  }

  std::string flags;
  static const std::unordered_set<char> allowed_flags = {'g', 'L'};
  std::unordered_set<char> seen;
  for (; pos < rule.size(); ++pos) {
    char current_char = rule[pos];
    if(std::isalpha(current_char, loc) &&
      !seen.count(current_char) &&
      allowed_flags.count(current_char))
    {
      flags += current_char;
      seen.insert(current_char);
    } else if (seen.count(current_char)){
      LOG(ERROR) << "Duplicate flag detected in sed rule " << sed_rule ;
      return std::nullopt;
    } else if (current_char == delimiter){
      continue;
    } else if (!allowed_flags.count(current_char)) {
      LOG(ERROR) << "Invalid flag in sed rule: " << current_char ;
      return std::nullopt;
    } else {
      LOG(ERROR) << "Unexpected character in sed rule flags: " << current_char ;
      return std::nullopt;
    }
  }

  if (part[0].empty()) {
    LOG(ERROR) << "Pattern cannot be empty";
    return std::nullopt;
  }

  if (escape) {
    LOG(ERROR) << "Trailing backslash in sed rule";
    return std::nullopt;
  }

  std::optional<std::string> processed_pattern = processJavaRegexLiterals(part[0]);
  if (processed_pattern.has_value()) {
    part[0] = processed_pattern.value();
    try {
      match_regex =  std::regex(part[0], std::regex::ECMAScript);
    } catch (const std::regex_error& e) {
      LOG(ERROR) << "Invalid sed rule pattern in rule: " << sed_rule << " - " << e.what() ;
      return std::nullopt;
    }
  }

  return SedRule{
    .pattern = part[0], 
    .replacement = part[1], 
    .flags = flags, 
    .compiled_pattern = match_regex};
}

std::optional<std::array<std::string, HadoopAuthToLocal::kParseFields>> 
HadoopAuthToLocal::parseAuthToLocalRule(const std::string& rule)
{
  std::locale loc("");

  enum class State {NUMBER, FORMAT, MATCH, SED, DONE};

  constexpr size_t match_field = 2;
  constexpr size_t sed_field = 3;

  if(rule.empty()) {
    LOG(WARNING) << "Empty rule provided for HadoopAuthToLocal::parseAuthToLocalRule";
    return std::nullopt;
  }
  const std::string prefix = "RULE:[";
  size_t pos = prefix.length();

  std::array<std::string, HadoopAuthToLocal::kParseFields> string_parts;

  size_t string_parts_idx = 0;

  std::string auth_rule = rule;
  State state = State::NUMBER;
  
  StripWhiteSpace(&auth_rule);


  if(auth_rule == "DEFAULT"){
    return std::array<std::string, HadoopAuthToLocal::kParseFields> {"0", "DEFAULT", "", ""};
  }

  if(auth_rule.rfind(prefix, 0) != 0 ){
    LOG(ERROR) << "Invalid rule format: " << auth_rule;
    LOG(ERROR) << "Expected: " << prefix << " at beginning of rule";
    return std::nullopt;
  }

  for(auto str : string_parts) {
    str.reserve(auth_rule.length());
  }
  
  bool escape = false;
  int paren_count = 0;
  
  while(pos < auth_rule.length() && state != State::DONE){
    char current_char = auth_rule[pos];
    
    switch(state){
      case State::NUMBER: {
        if(std::isdigit(current_char, loc)){
          string_parts[string_parts_idx] += current_char;
        } else if (current_char == ':') {
          if(string_parts[string_parts_idx].empty()){
            LOG(ERROR) << "Expected a number before ':' in rule: " << auth_rule;
            return std::nullopt;
          }
          state = State::FORMAT;
          string_parts_idx += 1;
          escape = false;
          
        } else {
          LOG(ERROR) << "Expected a digit or ':' at char " << pos + 1 << ", got '" 
            << current_char << "' instead";
          return std::nullopt;
        }
        break;
      }
      case State::FORMAT: {
        if(current_char == ']' && !escape){
          if (string_parts[string_parts_idx].empty()) {
            LOG(ERROR) << "Expected a format string before ']' in rule: " << auth_rule ;
            return std::nullopt;
          }
          state = State::MATCH;
          string_parts_idx += 1;
          escape = false;
        } else if (current_char == '\\' && !escape){
          escape = true;
        } else {
          escape = false;
          string_parts[string_parts_idx] += current_char;
        }
        break;
      }
      //This is an optional field
      case State::MATCH: {
        if (paren_count < 0){
          LOG(ERROR) << "Unmatched parentheses in rule: " << auth_rule ;
          return std::nullopt;
        } 

        if (paren_count == 0 && current_char != '('){
          state = State::SED;
          string_parts_idx += 1;
          continue;
        }
        if (paren_count == 0 && current_char == '(' && !escape){
          paren_count +=1;
        } else if (current_char == ')' && paren_count == 1 && !escape){
          state = State::SED;
          string_parts_idx += 1;
          --paren_count;
        } else if (escape){
          string_parts[string_parts_idx] += current_char;
          escape = false;
        } else if (current_char == '\\'){
          escape = true;
          string_parts[string_parts_idx] += current_char;
        } else {
          if (current_char == '(') {
            ++paren_count;
          } else if (current_char == ')') {
            --paren_count;
          }
          string_parts[string_parts_idx] += current_char;
        }
        break;
      }
      //This is an optional field
      case State::SED: {
        size_t sed_end = string_parts[string_parts_idx].find_last_not_of(" \t\f\v\n\r");
        if(sed_end != std::string::npos){
          string_parts[sed_field] = "";
        } else {
          string_parts[sed_field] = auth_rule.substr(pos, sed_end - pos); 
        }
        if(string_parts[sed_field].length() > 0 && string_parts[sed_field][0] != 's'){
          LOG(ERROR) << "Unexpected character at " << pos + 1 << " '" << 
            string_parts[sed_field][0] << "' in rule: " << auth_rule;
          return std::nullopt;
        }
        state = State::DONE;

        break;
      }
      default: {
        LOG(ERROR) << "Unexpected state while parsing auth_to_local rule " << auth_rule ;
      }
    }
    ++pos;
    
  }
  if(state == State::SED && string_parts[sed_field].empty()) {
    state = State::DONE;
  }

  if(state == State::MATCH && string_parts[match_field].empty()){
    state = State::DONE;
  }

  if(escape){
    LOG(ERROR) << "Trailing backslash in rule: " << auth_rule;
    return std::nullopt;
  }

  if (paren_count != 0) {
    LOG(ERROR) << "Unmatched parentheses in rule: " << auth_rule;
    return std::nullopt;
  }

  if (state != State::DONE){
    LOG(ERROR) << "Unexpected end of rule while parsing auth_to_local rule: " << auth_rule;
    return std::nullopt;
  }
  
  std::optional<std::string> match_field_processed = 
    processJavaRegexLiterals(string_parts[match_field]);

  if (match_field_processed.has_value()) {
    string_parts[match_field] = match_field_processed.value();
  } else {
    LOG(ERROR) << "Failed to process regex literals in match field: " << string_parts[match_field];
    return std::nullopt;
  }
  return string_parts;
}

std::optional<HadoopAuthToLocal::Rule> HadoopAuthToLocal::initRule(const std::string &auth_rule){
  if (auth_rule.empty()){
    LOG(ERROR) << "Unexpected empty auth rule in HadoopAuthToLocal::initRule";
    return std::nullopt;
  }
  std::string trimmed = auth_rule;
  StripWhiteSpace(&trimmed);
  auto auth_to_local = parseAuthToLocalRule(trimmed);

  if(auth_to_local.has_value()){
    auto [num_fields, format_string, regex_match_str, sed_rule] = auth_to_local.value();
    if (format_string != "DEFAULT" && (num_fields.empty() || format_string.empty())) {
      LOG(ERROR) << "Invalid rule format: " << auth_rule;
      return std::nullopt;
    }
    Rule rule = 
      {
        .numberOfFields = std::stoi(num_fields),
        .fmt = format_string,
        .rule = auth_rule,
        .regexMatchString = regex_match_str,
        .sedRule = parseSedRule(sed_rule),
        
      };

    if(!sed_rule.empty() && !rule.sedRule.has_value()) {
      LOG(ERROR) << "Failed to parse sed rule in: " << auth_rule;
      return std::nullopt;
    }

    try {
      rule.regexMatch = std::regex(regex_match_str, std::regex::ECMAScript);
    } catch (const std::regex_error& e) {
      LOG(ERROR) << "Invalid regex in rule: " << auth_rule << " - " << e.what();
      return std::nullopt;
    }
    
    return rule;
  }
  LOG(ERROR) << "Failed to parse rule: " << auth_rule;
  return std::nullopt;
}

int HadoopAuthToLocal::numberOfFields(std::string_view principal){
  size_t at_pos = principal.find('@');
  if (!checkPrincipal(principal, at_pos)){
    return -1;
  }
  std::string_view principal_without_realm = principal.substr(0, at_pos);
  std::string::difference_type slash_count = std::count(
    principal_without_realm.begin(),
    principal_without_realm.end(),
    '/');

  int count = static_cast<int>(slash_count);
  // Count is the number of slashes, but we want the actual number of fields separated by the slashes, so one extra.
  return count + 1;
}

std::vector<std::string> HadoopAuthToLocal::extractFields(std::string_view principal){
  size_t at_pos = principal.find('@');
  if(!checkPrincipal(principal, at_pos)){
    return std::vector<std::string>{};
  }
  std::vector<std::string> fields = strings::Split(
    std::string(principal.substr(0, at_pos)),
    "/", 
    strings::SkipWhitespace());

  fields.insert(fields.begin(),  std::string(principal.substr(at_pos + 1)) );
  return fields;
}

std::string HadoopAuthToLocal::getRealm(const std::string_view principal, size_t at_pos){
  if (at_pos == kAtPosDefault){
    at_pos = principal.find('@');
  }
  if(!checkPrincipal(principal, at_pos)){
    LOG(WARNING) << "Invalid principal format: " << principal;
    return "";
  }
  return std::string(principal.substr(at_pos + 1));
}

bool HadoopAuthToLocal::matchNumberOfFields(const Rule& rule, std::string_view principal) const{
  if(rule.fmt == "DEFAULT" && getRealm(principal) == this->defaultRealm_) {
    return true;
  }
  int fields = numberOfFields(principal);
  return rule.numberOfFields == fields;
}

std::optional<std::string> HadoopAuthToLocal::replaceMatchingPrincipal(
  const Rule& rule, 
  const std::string& formatted_principal)
{
  if (!rule.sedRule.has_value()){
    return std::nullopt; 
  }

  std::regex_constants::match_flag_type regex_replace_flags = std::regex_constants::format_first_only;
  bool lowercase_output = false;

  if(!std::regex_match(formatted_principal, rule.regexMatch) && rule.regexMatchString.length() > 0) {
    return std::nullopt;
  }

  //Hadoop auth_to_local rules only support the 'g' and 'L' flags.
  //The 'L' flag is a Hadoop specific extension to lowercase the output.
  if (auto sed = rule.sedRule){
    if(!sed->flags.empty()){
      if(sed->flags.find('g') != std::string::npos){
        regex_replace_flags = std::regex_constants::match_default;
      }
      //This is a hadoop specific extension.
      if(sed->flags.find('L') != std::string::npos){
        lowercase_output = true;
      }
    }
  }
  std::string output = std::regex_replace(
    formatted_principal, 
    rule.sedRule.value().compiled_pattern, 
    rule.sedRule.value().replacement, 
    regex_replace_flags);

  if(lowercase_output) {
    std::transform(output.begin(), output.end(), output.begin(), ::tolower);
  }
  return output;
}

bool HadoopAuthToLocal::checkPrincipal(std::string_view principal, size_t at_pos ){
  if(principal.empty()){
    LOG(WARNING) << "Principal cannot be empty";
    return false;
  }

  if (at_pos == kAtPosDefault ){
    at_pos = principal.find('@');
  }
  
  if (at_pos == std::string::npos || 
    principal.substr(at_pos+1).empty() ||
    principal.substr(0, at_pos).empty())
  {
    return false;
  }

  size_t at_count = std::count(principal.begin(), principal.end(), '@');
  
  if(at_count != 1){
    return false;
  }

  if (principal.substr(0,at_pos).empty()){
    return false;
  }

  std::locale loc("");
  for(size_t idx=0; idx < principal.length(); idx++){
    if(std::isspace(principal[idx], loc)){
      LOG(WARNING) << "Principal cannot contain whitespace characters: " << principal;
      return false;
    }
  }

  return true;
}

bool HadoopAuthToLocal::simplePatternCheck(std::string_view short_name) const{
  if(this->ruleMechanism_ == RuleMechanism::HADOOP) { 
    if (short_name.find('@') != std::string::npos || short_name.find('/') != std::string::npos) {
      LOG(WARNING) << "Short name cannot contain both '@' and '/' characters: " << short_name;
      return false;
    }
  }

  return true;
}

std::optional<std::string> HadoopAuthToLocal::defaultRule(
  const Rule& rule, 
  const std::string& principal, 
  std::string_view realm) const
{
  if (rule.fmt == "DEFAULT" && realm == this->defaultRealm_) {
    std::vector<std::string> fields = extractFields(principal);
    if(fields.size() > 1){
      return fields[1];
    }
  }
  return std::nullopt;
}

std::optional<std::string> HadoopAuthToLocal::createFormattedPrincipal(
  const Rule& rule, 
  const std::vector<std::string>& principal_fields) const
{
  if (principal_fields.size() < 2) {
    LOG(ERROR) << "Principal must have at least two fields for formatting: " << rule.rule;
    return std::nullopt;
  }
  if (rule.fmt == "DEFAULT") {
    return defaultRule(rule, principal_fields[1], principal_fields[0]);
  }
  
  return format(rule.fmt, principal_fields);
}

std::optional<std::string> HadoopAuthToLocal::transformPrincipal(
  const Rule& rule, 
  std::string_view principal) const
{
  if(!checkPrincipal(principal)){
    return std::nullopt;
  }
  std::string realm = getRealm(principal);
  if (rule.fmt == "DEFAULT" && realm == this->defaultRealm_) {
    std::vector<std::string> fields = extractFields(principal);
    if(fields.size() >= 2){
      return fields[1];
    }
    LOG(ERROR) << "Principal does not have enough fields for DEFAULT rule: " << principal;
    return std::nullopt;
  } 

  if (rule.fmt == "DEFAULT" && realm != this->defaultRealm_) {
    return std::nullopt;
  }

  if (!matchNumberOfFields(rule,principal)){
    return std::nullopt;
  }
  std::vector<std::string> fields = extractFields(principal);
  std::optional<std::string> formattedShortRule = createFormattedPrincipal(rule, fields );
  if (!formattedShortRule.has_value()) {
    return std::nullopt;
  }
  std::optional<std::string> output = replaceMatchingPrincipal(rule, formattedShortRule.value());
  
  if (output.has_value() && simplePatternCheck(output.value())) {
    return output;
  }
  return std::nullopt;

}

std::optional<std::string> HadoopAuthToLocal::matchPrincipalAgainstRules(
  std::string_view principal) const
{
  std::shared_lock<std::shared_mutex> lock(mutex_);

  if(rules_.empty()) {
    LOG(ERROR) << "No auth_to_local rules loaded from Hadoop configuration";
    return std::nullopt;
  }

  for (const auto &rule : rules_) {
    
    std::optional<std::string> new_principal = transformPrincipal(rule, principal);
    if(new_principal.has_value()) {
      LOG(INFO) << "Transformed principal: " << principal << " to " << new_principal.value() << " using rule: " << rule.rule;
      return new_principal;
    }
  }
  return std::nullopt;
}

} // namespace security
} // namespace kudu
