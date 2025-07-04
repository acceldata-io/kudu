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

HadoopAuthToLocal::HadoopAuthToLocal(const std::string& filepath, krb5_context& ctx) {
  setKrb5Context(ctx);
  loadConf(filepath);
}

//used for tests
HadoopAuthToLocal::HadoopAuthToLocal(){
  defaultRealm_ = "";
  coreSiteRules_ = std::vector<std::string>{};
}

//Private function used only for tests
void HadoopAuthToLocal::setDefaultRealm(const std::string& realm) {
  std::unique_lock<std::shared_mutex> lock(mutex_);
  defaultRealm_ = realm;
  StripWhiteSpace(&defaultRealm_);
}

std::vector<std::string> HadoopAuthToLocal::getRules() {
  return this->coreSiteRules_;
}

int HadoopAuthToLocal::setKrb5Context(krb5_context& ctx){
  std::unique_lock<std::shared_mutex> lock(mutex_);
  char *realm = nullptr;
  krb5_error_code err = krb5_get_default_realm(ctx, &realm);
  if(err){
    krb5_free_default_realm(ctx, realm);
    LOG(ERROR) << "Failed to get default realm from krb5 context: " << err << "\n";
    return -1;
  }
  defaultRealm_ = std::string(realm);
  StripWhiteSpace(&defaultRealm_);
  krb5_free_default_realm(ctx, realm);
  return 0;
}

int HadoopAuthToLocal::loadConf(const std::string& filepath) {
  char buffer[PATH_MAX];
  std::string canonical_path; 
  if(realpath(filepath.c_str(), buffer)){
    canonical_path = std::string(buffer);
  }
  else {
    LOG(ERROR) << "Failed to resolve real path for " << filepath << ": " << strerror(errno) << "\n";
  }

  const std::string ext = ".xml";
  if (canonical_path.length() < ext.length() ||
    canonical_path.compare(canonical_path.length() - ext.length(), ext.length(), ext) != 0) {
    LOG(ERROR) << "HadoopAuthToLocal configuration file must be an XML file, but got: " << canonical_path << "\n";
    return -1;
  }

  std::ifstream file_stream(canonical_path);
  if(!file_stream.is_open()) {
    LOG(ERROR) << "Failed to open HadoopAuthToLocal configuration file: " << canonical_path << "\n";
    return -1;
  }
  return setRules(file_stream);
}

int HadoopAuthToLocal::setRules(std::istream& input) {
  std::unique_lock<std::shared_mutex> lock(mutex_);
  this->coreSiteRules_.clear();
  std::vector<std::string> rules;
  boost::property_tree::ptree tree;
  try {
      read_xml(input, tree);
  } catch (const boost::property_tree::xml_parser_error& e) {
     LOG(ERROR) << "Malformed XML when loading from core-site.xml\n";
    return -1;
  }

  if(tree.find("configuration") == tree.not_found()) {
    LOG(ERROR) << "No <configuration> section found in core-site.xml\n";
    return -1;
  }
  
  for (const auto &property : tree.get_child("configuration")){
    if(property.first == "property") {
      std::string name = property.second.get<std::string>("name", "");
      if (name == "hadoop.security.auth_to_local") {
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
    for (auto &rule : this->coreSiteRules_) {
      std::optional<Rule> new_rule = initRule(rule);
      if (new_rule.has_value()) {
        this->rules_.push_back(new_rule.value());
      } else {
        LOG(WARNING) << "Invalid rule: " << rule << "\n";
      }
    }
    return 0;
  }
  return -1;
}

std::optional<std::vector<HadoopAuthToLocal::Token>> HadoopAuthToLocal::tokenize(const std::string &fmt) {
  std::locale loc("");
  std::vector<Token> tokens;
  tokens.reserve(fmt.length());
  if (fmt.empty()) {
    LOG(ERROR) << "Empty format string provided for HadoopAuthToLocal::tokenize\n";
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

std::optional<std::string> HadoopAuthToLocal::format(const std::string& fmt, const std::vector<std::string>& values) {
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
                   << ", but only " << values.size() << " values provided.\n";
        return std::nullopt;
      }
    } else if (token.type == Token::Type::literal) {
      result.append(token.text);
    }
  }
  return result;
}

std::string HadoopAuthToLocal::escapeJavaRegexLiteral(const std::string& input){
  static const std::string metachars = R"(.^$|()[]\{}*+?)";
  std::string output;
  output.reserve(input.size() * 2); 

  for (char current_char : input) {
    if (metachars.find(current_char) != std::string::npos) {
      output.push_back('\\');
    }
    output.push_back(current_char);
  }
  return output;
}

std::string HadoopAuthToLocal::processJavaRegexLiterals(const std::string& input) {
  std::string output;
    
  for (size_t idx = 0; idx < input.size();) {
    if (input.substr(idx, 2) == "\\Q") {
      idx += 2;
      size_t end = input.find("\\E", idx);
      if (end == std::string::npos) {
        LOG(ERROR) << "Unterminated \\Q in regex literal " << input << "\n";
        return input;
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

std::string HadoopAuthToLocal::SedBackslashEscape(const std::string& input){
  std::string regex_pattern;
  regex_pattern.reserve(input.size() * 2);

  for (size_t idx = 0; idx < input.size(); ++idx) {
    if (input[idx] == '\\') {
      regex_pattern += "\\\\";
    }
    else{
      regex_pattern += input[idx];
    }
  }
  return regex_pattern;
}

std::optional<HadoopAuthToLocal::SedRule> HadoopAuthToLocal::parseSedRule(const std::string& sed_rule){
  std::locale loc("");
  if (sed_rule.empty()) {  
    return std::nullopt;
  }
  if (sed_rule.size() < 3 || sed_rule[0] != 's') {
    LOG(ERROR) << "Rule must start with 's' and a delimiter\n";
    LOG(ERROR) << "It is: '" << sed_rule << "'\n";
    return std::nullopt;
  }
  const char delimiter = sed_rule[1];
  //Absolute max size of any part of a sed rule
  constexpr size_t max_size = 128;

  std::string rule = sed_rule.substr(2); //skip the s + delimiter
  size_t pos = 0; 
  std::string part[2];
  int part_idx = 0;
  bool escape = false;
  std::regex match_regex;
    
  if (std::isalnum(delimiter, loc) || std::isspace(delimiter, loc) ||  delimiter == '\\' || delimiter == '@') {
    LOG(ERROR) << "Invalid delimiter in sed rule: '" << delimiter << "'\n";
    return std::nullopt;
  }

  while (pos < rule.size() && part_idx < 2) {
    if(part[part_idx].size() >= max_size) {
      LOG(ERROR) << "Part " << part_idx + 1 << "of sed rule " << sed_rule << " is too long: " << rule.size() << " characters. Max 128.\n";
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
        LOG(ERROR) << "Sed rule has too many parts: " << sed_rule << "\n";
        return std::nullopt;
      }
    } else {
      part[part_idx] += current_char;
    }
    ++pos;
  }

  if (part_idx != 2 ) {
    LOG(ERROR) << "Malformed sed rule: " << sed_rule << "\n";
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
      LOG(ERROR) << "Duplicate flag detected in sed rule " << sed_rule << "\n";
      return std::nullopt;
    } else if (current_char == delimiter){
      continue;
    } else if (!allowed_flags.count(current_char)) {
      LOG(ERROR) << "Invalid flag in sed rule: " << current_char << "\n";
      return std::nullopt;
    } else {
      LOG(ERROR) << "Unexpected character in sed rule flags: " << current_char << "\n";
      return std::nullopt;
    }
  }

  if (part[0].empty()) {
    LOG(ERROR) << "Pattern cannot be empty\n";
    return std::nullopt;
  }

  if (escape) {
    LOG(ERROR) << "Trailing backslash in sed rule\n";
    return std::nullopt;
  }

  if(!part[0].empty()) {
    try {
      part[0] = processJavaRegexLiterals(part[0]);
      match_regex =  std::regex(part[0], std::regex::ECMAScript);
    } catch (const std::regex_error& e) {
      LOG(ERROR) << "Invalid sed rule pattern in rule: " << sed_rule << " - " << e.what() << "\n";
      return std::nullopt;
    }
  }

  return SedRule{.pattern = part[0], .replacement = part[1], .flags = flags, .compiled_pattern = match_regex};
}

std::optional<std::array<std::string, HadoopAuthToLocal::kParseFields>> HadoopAuthToLocal::parseAuthToLocalRule(const std::string& rule){
  std::locale loc("");
  if(rule.empty()) {
    LOG(WARNING) << "Empty rule provided for HadoopAuthToLocal::parseAuthToLocalRule\n";
    return std::nullopt;
  }
  const std::string prefix = "RULE:[";
  size_t pos = prefix.length();
  std::string number="";
  std::string format="";
  std::string regex_match="";
  std::string sed_rule="";
  std::string auth_rule = rule;
  StripWhiteSpace(&auth_rule);


  if(auth_rule == "DEFAULT"){
    return std::array<std::string, HadoopAuthToLocal::kParseFields> {"0", "DEFAULT", "", ""};
  }
  if(auth_rule.rfind(prefix, 0) != 0 ){
    LOG(ERROR) << "Invalid rule format: " << auth_rule << "\n";
    LOG(ERROR) << "Expected: " << prefix << " at beginning of rule\n";
    return std::nullopt;
  }
  

  while(pos < auth_rule.length() && isdigit(auth_rule[pos], loc)){
    number += auth_rule[pos];
    ++pos;
  }
  if (pos >= auth_rule.length() || auth_rule[pos] != ':') {
    LOG(ERROR) << "Expected ':' at char " << pos << ", got " << auth_rule[pos] << "instead\n";
    return std::nullopt;
  }
  

  bool escape = false;
  while (++pos < auth_rule.length() ) {
    char current_char = auth_rule[pos];
    if (escape) {
      format += current_char;
      escape = false;
    } else if (current_char == '\\') {
      escape = true;
    } else if (current_char == ']') {
      break;
    } else {
      format += current_char;
    }
  }

  if(auth_rule[pos] != ']'){
    LOG(ERROR) << "Expected ']' at char " << pos + 1 << ", got '" << auth_rule[pos] << "' instead \n";
    return std::nullopt;
  }

  if(pos>= auth_rule.length() || auth_rule[pos + 1] != '('){

    LOG(ERROR) << "Expected '(' at char " << pos + 1 << " in "<< auth_rule << "\n";
    LOG(ERROR) << "Got " << auth_rule[pos] << " instead\n";
    return std::nullopt;
  }
  //Move past the '('
  ++pos;
  int parens_count = 1;

  escape = false;
  while (++pos < auth_rule.length()) {
    char current_char = auth_rule[pos];
    if (escape){
      regex_match += current_char;
      escape = false;
    }
    else if (current_char == '\\'){
      regex_match += current_char;
      escape = true;
    } else if (current_char == '(') {
      regex_match += current_char;
      ++parens_count;
    } else if (current_char == ')'){
      --parens_count;
      if(parens_count == 0){
        break; //we found the closing parenthesis
      }
      if (parens_count < 0) {
        LOG(ERROR) << "Unexpected closing parenthesis at char " << pos << " in rule: " << auth_rule << "\n";
        return std::nullopt;
      }
      regex_match += current_char; 
      
    } else {
      regex_match += current_char;
    }
  }
  
  if(parens_count != 0 ){
    LOG(ERROR) << "Unmatched opening parenthesis in rule: " << auth_rule << "\n" ;
    return std::nullopt;
  }

  if(auth_rule[pos ] != ')'){
    LOG(ERROR) << "Expected ')' at char " << pos + 1 << ", got '" << auth_rule[pos] << "' instead \n";
    return std::nullopt;
  }
  if(regex_match.empty()){
    LOG(ERROR) << "Regex match string cannot be empty in rule: " << auth_rule << "\n";
    return std::nullopt;
  }
  regex_match = processJavaRegexLiterals(regex_match);
  //Move past the ')'
  if (++pos < auth_rule.length()){
    sed_rule = auth_rule.substr(pos);
  }

  StripWhiteSpace(&number);
  StripWhiteSpace(&format);
  StripWhiteSpace(&regex_match);
  StripWhiteSpace(&sed_rule);

  return std::array<std::string, HadoopAuthToLocal::kParseFields>{ number, format, regex_match, sed_rule };
}

std::optional<HadoopAuthToLocal::Rule> HadoopAuthToLocal::initRule(const std::string &auth_rule){
  if (auth_rule.empty()){
    LOG(ERROR) << "Unexpected empty auth rule in HadoopAuthToLocal::initRule\n";
    return std::nullopt;
  }
  std::string trimmed = auth_rule;
  StripWhiteSpace(&trimmed);
  auto auth_to_local = parseAuthToLocalRule(trimmed);

  if(auth_to_local.has_value()){
    auto [num_fields, format, regex_match_str, sed_rule] = auth_to_local.value();
    if (format != "DEFAULT" && (num_fields.empty() || format.empty() || regex_match_str.empty())) {
      LOG(ERROR) << "Invalid rule format: " << auth_rule << "\n";
      return std::nullopt;
    }
    Rule rule = 
      {
        .numberOfFields = std::stoi(num_fields),
        .fmt = format,
        .rule = auth_rule,
        .regexMatchString = regex_match_str,
        .sedRule = parseSedRule(sed_rule),
        
      };
    if(!sed_rule.empty() && !rule.sedRule.has_value()) {
      LOG(ERROR) << "Failed to parse sed rule in: " << auth_rule << "\n";
      return std::nullopt;
    }

    try {
      rule.regexMatch = std::regex(regex_match_str, std::regex::ECMAScript);
    } catch (const std::regex_error& e) {
      LOG(ERROR) << "Invalid regex in rule: " << auth_rule << " - " << e.what() << "\n";
      return std::nullopt;
    }
    
    return rule;
  }
  LOG(ERROR) << "Failed to parse rule: " << auth_rule << "\n";
  return std::nullopt;
}

int HadoopAuthToLocal::numberOfFields(const std::string& principal){
  size_t at_pos = principal.find('@');
  if (!checkPrincipal(principal, at_pos)){
    return -1;
  }
  std::string principal_without_realm = principal.substr(0, at_pos);
  std::string::difference_type slash_count = std::count(principal_without_realm.begin(), principal_without_realm.end(), '/');
  int count = static_cast<int>(slash_count);
  // Count is the number of slashes, but we want the actual number of fields separated by the slashes, so one extra.
  return count + 1;
}

std::vector<std::string> HadoopAuthToLocal::extractFields(const std::string &principal){
  size_t at_pos = principal.find('@');
  if(!checkPrincipal(principal, at_pos)){
    return std::vector<std::string>{};
  }
  std::vector<std::string> fields = strings::Split(principal.substr(0, at_pos),"/", strings::SkipWhitespace());
  fields.insert(fields.begin(),  principal.substr(at_pos + 1) );
  return fields;
}

std::string HadoopAuthToLocal::getRealm(const std::string& principal, size_t at_pos){
  if (at_pos == kAtPosDefault){
    at_pos = principal.find('@');
  }
  if(!checkPrincipal(principal, at_pos)){
    LOG(WARNING) << "Invalid principal format: " << principal << "\n";
    return "";
  }
  return principal.substr(at_pos + 1);
}

bool HadoopAuthToLocal::matchNumberOfFields(const Rule& rule, const std::string& principal){
  if(rule.fmt == "DEFAULT" && getRealm(principal) == this->defaultRealm_) {
    return true;
  }
  int fields = numberOfFields(principal);
  return rule.numberOfFields == fields;
}

std::optional<std::string> HadoopAuthToLocal::replaceMatchingPrincipal(const Rule& rule, const std::string& formatted_principal){
  if (!rule.sedRule.has_value()){
    return std::nullopt; 
  }

  std::regex_constants::match_flag_type regex_replace_flags = std::regex_constants::format_first_only;
  bool lowercase_output = false;

  if(!std::regex_match(formatted_principal, rule.regexMatch)){
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
    LOG(WARNING) << "Principal cannot be empty\n";
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
      LOG(WARNING) << "Principal cannot contain whitespace characters: " << principal << "\n";
      return false;
    }
  }

  return true;
}

std::optional<std::string> HadoopAuthToLocal::defaultRule(const Rule& rule, const std::string& principal, const std::string& realm){
  if (rule.fmt == "DEFAULT" && realm == this->defaultRealm_) {
    std::vector<std::string> fields = extractFields(principal);
    if(fields.size() > 1){
      return fields[1];
    }
  }
  return std::nullopt;
}

std::optional<std::string> HadoopAuthToLocal::createFormattedPrincipal(const Rule& rule, const std::vector<std::string>& principal_fields){
  if (principal_fields.size() < 2) {
    LOG(ERROR) << "Principal must have at least two fields for formatting: " << rule.rule << "\n";
    return std::nullopt;
  }
  if (rule.fmt == "DEFAULT") {
    return defaultRule(rule, principal_fields[1], principal_fields[0]);
  }
  
  return format(rule.fmt, principal_fields);
}

std::optional<std::string> HadoopAuthToLocal::transformPrincipal(const Rule& rule, const std::string& principal){
  if(!checkPrincipal(principal)){
    return std::nullopt;
  }
  std::string realm = getRealm(principal);
  if (rule.fmt == "DEFAULT" && realm == this->defaultRealm_) {
    std::vector<std::string> fields = extractFields(principal);
    if(fields.size() >= 2){
      return fields[1];
    }
    LOG(ERROR) << "Principal does not have enough fields for DEFAULT rule: " << principal << "\n";
    return std::nullopt;
  } else if (rule.fmt == "DEFAULT" && realm != this->defaultRealm_) {
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
  return replaceMatchingPrincipal(rule, formattedShortRule.value()) ;

}

std::optional<std::string> HadoopAuthToLocal::matchPrincipalAgainstRules(const std::string &principal){
  std::shared_lock<std::shared_mutex> lock(mutex_);

  if(rules_.empty()) {
    LOG(ERROR) << "No auth_to_local rules loaded from Hadoop configuration\n";
    return std::nullopt;
  }

  for (const auto &rule : rules_) {
    
    std::optional<std::string> new_principal = transformPrincipal(rule, principal);
    if(new_principal.has_value()) {
      LOG(INFO) << "Transformed principal: " << principal << " to " << new_principal.value() << " using rule: " << rule.rule << "\n";
      return new_principal;
    }
  }
  return std::nullopt;
}

} // namespace security
} // namespace kudu
