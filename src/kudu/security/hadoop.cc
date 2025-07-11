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
#include <boost/foreach.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <climits> //Used for PATH_MAX
#include <csignal>
#include <glog/logging.h>
#include <krb5/krb5.h>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <string>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
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

//Load the default realm from krb5_context
bool HadoopAuthToLocal::setKrb5Context(krb5_context& ctx){
  //With a unique lock, nothing else is allowed to write until it's released automatically
  //when we return from the function
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

//Try to load the core-site.xml file that's been passed
bool HadoopAuthToLocal::loadConf(const std::string& filepath) {
  //This uses a c function to check that the actual real path exists, in case there's a symlink
  char buffer[PATH_MAX];
  std::string canonical_path; 
  if(realpath(filepath.c_str(), buffer)){
    canonical_path = std::string(buffer);
  }
  else {
    LOG(ERROR) << "Failed to resolve real path for " << filepath << ": " << strerror(errno) ;
    return false;
  }

  //Make sure we're reading an xml file
  const std::string ext = ".xml";
  if (canonical_path.length() < ext.length() ||
    canonical_path.compare(canonical_path.length() - ext.length(), ext.length(), ext) != 0) {
    LOG(ERROR) << "HadoopAuthToLocal configuration file must be an XML file, but got: " << canonical_path ;
    return false;
  }

  //We convert the contents to an ifstream. This is mostly to make testing easier,
  //since a ifstream can be either a string or a file
  std::ifstream file_stream(canonical_path);
  if(!file_stream.is_open()) {
    LOG(ERROR) << "Failed to open HadoopAuthToLocal configuration file: " << canonical_path ;
    return false;
  }
  return setRules(file_stream);
}

bool HadoopAuthToLocal::setRules(std::istream& input) {
  //Nothing else is allowed to read or write until this mutex goes out of scope
  std::unique_lock<std::shared_mutex> lock(mutex_);
  this->coreSiteRules_.clear();
  this->rulesByFields_.clear();
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
  
  //Walk through the xml to find the two properties we're looking for
  for (const auto &property : tree.get_child("configuration")){
    if(property.first == "property") {
      std::string name = property.second.get<std::string>("name", "");
      //When set to hadoop (the default), neither '@' or '/' are allowed in the final shortened
      //name. Mit means we just return whatever the end result is
      if (name == "hadoop.security.auth_to_local.mechanism"){
        if(property.second.get<std::string>("value", "HADOOP") == "MIT"){
          ruleMechanism_ = RuleMechanism::MIT;
        } else {
          ruleMechanism_ = RuleMechanism::HADOOP;
        }
      }
      else if (name == "hadoop.security.auth_to_local") {
        std::string value = property.second.get<std::string>("value", "");
        
        //Walk through the rules and remove windows line endings with unix ones
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

  //This populates a vector with all non-empty strings found in the passed core-site.xml
  for (auto &rule : rules){
    StripWhiteSpace(&rule);
    if(!rule.empty()){

      this->coreSiteRules_.push_back(rule);
    }
  }

  //Initialize all the rules
  if (this->coreSiteRules_.size() > 0) {
    for (const auto &rule : this->coreSiteRules_) {
      std::optional<Rule> new_rule = initRule(rule);
      if (new_rule.has_value() ) {
        //This map is organized by the number of fields in the rule.
        //A principal can only match against a rule if it has the same number of fields
        //Except for DEFAULT, which is handled as a special case
        this->rulesByFields_[new_rule->numberOfFields].push_back(new_rule.value());
      } else {
        LOG(WARNING) << "Invalid rule: " << rule ;
      }
    }
    return true;
  }
  return false;
}

//Turn a format string like $1@$0 and replace all placeholders with values from the vector 'values'
std::optional<std::string> HadoopAuthToLocal::format(const std::string& fmt, const std::vector<std::string>& values) const{
  //We deal with DEFAULT elsewhere
  if (fmt == "DEFAULT"){
    return std::nullopt;
  }
  std::string result;
  size_t pos = 0;
  while(pos < fmt.length()){
    const char current_char = fmt[pos];

    if (current_char == '\\' && pos + 1 < fmt.length() && fmt[pos + 1] == '$'){
      result += '$';
      pos += 2;
    }
    else if(current_char == '$'){
      size_t start = pos + 1;
      if(start < fmt.length() && std::isdigit(fmt[start], this->loc_)){
        size_t idx = 0;
        while(start < fmt.length() && std::isdigit(fmt[start], this->loc_)){
          //convert char to an integer
          idx = idx * 10 + (fmt[start] - '0');
          ++start;
        }
        if (idx < values.size()){
          result += values[idx];
          pos = start;
        } else {
          //out of bounds
          return std::nullopt;
        }
      } else {
        //invalid placeholder
        return std::nullopt;
      }
    } else {
      result += fmt[pos];
      ++pos;
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

//This adds support for Java regex escaping, \Q...\E. Anything between those that needs to be
//escaped is escaped using escapeJavaRegexLiteral
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

//Parse sed rules. There can be exactly one sed rule per rule, unlike mit kerberos
std::optional<HadoopAuthToLocal::SedRule> HadoopAuthToLocal::parseSedRule(std::string_view sed_rule) noexcept{
  if (sed_rule.empty()) {  
    return std::nullopt;
  }
  //Hadoop auth to local rules only allow '/' as a delimiter, unlike sed
  static constexpr char delimiter = '/';
  if (sed_rule.size() < 3 || sed_rule[0] != 's' || sed_rule[1] != delimiter) {
    LOG(ERROR) << "Rule must start with 's' and a delimiter";
    LOG(ERROR) << "It is: '" << sed_rule << "'";
    return std::nullopt;
  }
  //Absolute max size of any part of a sed rule
  static constexpr size_t max_size = 128;
 //skip the s + delimiter
  std::string_view rule = sed_rule.substr(2);
  size_t pos = 0; 
  std::string part[2];
  int part_idx = 0;
  bool escape = false;
  std::regex match_regex;

  //Walk through the rule
  while (pos < rule.size() && part_idx < 2) {
    if(part[part_idx].size() >= max_size) {
      LOG(ERROR) << "Part " << part_idx + 1 << "of sed rule " << sed_rule << " is too long: " << 
        rule.size() << " characters. Max " << max_size;
      return std::nullopt;
    }
    char current_char = rule[pos];
    //This prevents us from exiting out of the loop early if we encounter an escaped delimiter
    if (escape) {
      part[part_idx] += current_char;
      escape = false;
    } else if (current_char == '\\') {
      part[part_idx] += current_char;
      escape = true;
    } else if (current_char == delimiter ) {
      if(++part_idx > 2){
        LOG(ERROR) << "Sed rule has too many parts: " << sed_rule ;
        return std::nullopt;
      }
    } else {
      part[part_idx] += current_char;
    }
    ++pos;
  }

  //This probably means we have a bad rule 
  if (escape) {
    LOG(ERROR) << "Trailing backslash in sed rule";
    return std::nullopt;
  }

  //A sed rule must have both a pattern and a replacement. Whenever we get to this point,
  //we will have the actual number of parts + 1
  if (part_idx != 2 ) {
    LOG(ERROR) << "Malformed sed rule: " << sed_rule ;
    return std::nullopt;
  }
  
  //This should never be empty since the sed replace would be pointless without a pattern
  if (part[0].empty()) {
    LOG(ERROR) << "Pattern cannot be empty";
    return std::nullopt;
  }

  //Walk through the flags. These are optional, but must appear no more than once each.
  //This can be in /g/L format, or /gL (order is not important)
  std::optional<std::string> flags = parseSedFlags(rule.substr(pos), delimiter);
  if(!flags.has_value()){
    LOG(ERROR) << "Had issue with flags";
    return std::nullopt;
  }

  //Check for \Q..\E in the strings (Java regex feature)
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
    .flags = flags.value(), 
    .compiled_pattern = match_regex};
}

//This is used to parse the flags in a sed rule
//We only allow g and L flags, and they can appear in any order
std::optional<std::string> HadoopAuthToLocal::parseSedFlags(std::string_view flags, char delimiter) noexcept {
  static const std::unordered_set<char> allowed_flags = {'g', 'L'};
  std::string result;
  for (char flag : flags) {
    //Skip delimiter characters
    if(flag == delimiter) {
      continue;
    }
    if (allowed_flags.count(flag)) {
      if (result.find(flag) == std::string::npos) {
        result += flag;
      } else {
        LOG(ERROR) << "Duplicate flag detected in sed rule: " << flags ;
        return std::nullopt;
      }
    } else {
      LOG(ERROR) << "Invalid flag in sed rule: " << flag ;
      return std::nullopt;
    }
  }
  return result;
}

//This is so we can test the regex in a child process that we can kill if it takes too long
//This could happen if some bad input is passed to a slightly too permissive regex
std::optional<bool> HadoopAuthToLocal::try_match_regex(
  const std::regex& reg,
  const std::optional<SedRule>& sed_match_pattern,
  std::string_view match_string, 
  int milliseconds ) 
{
  static constexpr signed char SUCCESS = 1; 
  static constexpr signed char FAILURE = 0;
  static constexpr signed char ERROR = -1;

  //We aren't always guaranteed to have a sed pattern
  std::regex sed_match = sed_match_pattern.has_value() ? sed_match_pattern->compiled_pattern : std::regex({});

  int pipefd[2];
  if (pipe(pipefd) == -1) {
    LOG(ERROR) << "Failed to create pipe for regex compilation: " << strerror(errno);
    return std::nullopt;
  }
  pid_t pid = fork();
  if (pid < 0){
    close(pipefd[0]);
    close(pipefd[1]);
    return std::nullopt;
  }
  //child process
  if(pid == 0){
    close(pipefd[0]);
    signed char succeeded = 0;
    try {
      bool result = std::regex_match(match_string.begin(), match_string.end(), reg) &&
        std::regex_search(match_string.begin(), match_string.end(), sed_match);
      succeeded = result ? SUCCESS : FAILURE;
    } catch (...){
      //If something went wrong with the regex, we can assume this failed
      succeeded = ERROR;
    }
    write(pipefd[1], &succeeded, sizeof(succeeded));
    close(pipefd[1]);
    _exit(0);
  } else {
    close(pipefd[1]);
    fd_set set;
    FD_ZERO(&set);
    FD_SET(pipefd[0], &set);

    struct timeval timeout;
    if(milliseconds < 0 ){
      milliseconds = abs(milliseconds);
    }

    timeout.tv_sec =  milliseconds / 1000;
    // Convert milliseconds to microseconds
    timeout.tv_usec = (milliseconds % 1000) * 1000;

    int ret = select(pipefd[0] + 1, &set, nullptr, nullptr, &timeout);

    //Some value available
    if(ret == 1){
      signed char input = 2;
      ssize_t bytes_read = read(pipefd[0], &input, sizeof(input));
      close(pipefd[0]);
      int status;
      //clean up child
      waitpid(pid, &status, 0);
      if (bytes_read == 1){
        //ERROR means an exception was throw in the child process
        if (input == ERROR){
          return std::nullopt;
        }
        return input == SUCCESS;
      }
    } else {
      //If kill doesn't work, check why
      if(kill(pid, SIGKILL) == -1){
        if(errno == ESRCH) {
          DLOG(INFO) << "Child process already exited, no need to kill it";
        } else {
          LOG(ERROR) << "Failed to kill child process: " << strerror(errno);
        }
      }
      close(pipefd[0]);
      int status;
      waitpid(pid, &status, 0);
    }
  }

  return std::nullopt;
}

//Parse out each section of the rule. Each rule must start with RULE:[
//or it must be DEFAULT
std::optional<std::array<std::string, HadoopAuthToLocal::kParseFields>> 
  HadoopAuthToLocal::parseAuthToLocalRule(std::string_view rule)
{
  if(rule.empty()) {
    LOG(WARNING) << "Empty rule provided for HadoopAuthToLocal::parseAuthToLocalRule";
    return std::nullopt;
  }
  //Use the user's current locale to parse digits

  //Number is the field digit (IE how many fields are in the rule)
  //Format is the format string (IE $1@$0)
  //Match is the optional match rule in ()
  //Sed is whatever is the sed s/pattern/replacement/flags
  //Used for indexing the array containing the fields
  enum Field {
    Number = 0,
    Format = 1,
    Match = 2,
    Sed = 3,
  };

  constexpr std::string_view prefix = "RULE:[";
  //Each rule that isn't default must begin with 'RULE:['

  const size_t first_non_whitespace = rule.find_first_not_of(" \t\r\n");
  const size_t start = rule.find(prefix);
  const size_t last_non_whitespace = rule.find_last_not_of(" \t\r\n");
  const size_t start_pos = start + prefix.length();

  if (last_non_whitespace == std::string::npos || 
      last_non_whitespace < start_pos ||
      first_non_whitespace == std::string::npos) 
  {
    LOG(ERROR) << "Invalid rule format: " << rule;
    LOG(ERROR) << "Expected a non-empty rule after " << prefix;
    return std::nullopt;
  }
  
  //Treat DEFAULT as a special case since it doesn't follow the same format as everything else
  if(rule.substr(first_non_whitespace, last_non_whitespace - first_non_whitespace + 1) == "DEFAULT")
  {
    return std::array<std::string, HadoopAuthToLocal::kParseFields> {"0", "DEFAULT", "", ""};
  }

  if( start == std::string::npos ) {
    LOG(ERROR) << "Invalid rule format: " << rule;
    LOG(ERROR) << "Expected: " << prefix << " at beginning of rule";
    return std::nullopt;
  }

  std::string_view auth_rule = rule.substr(start_pos, last_non_whitespace - start_pos + 1);
  size_t pos = 0;

  //kParseFields is a contexpr that is defined in the header 
  std::array<std::string, HadoopAuthToLocal::kParseFields> fields;

  bool escape = false;
  //This is a mandatory field
  fields[Number] = parseNumberString(auth_rule, pos).value_or("");
  if(fields[Number].empty()){
    return std::nullopt;
  }
  //This is a mandatory field
  fields[Format] = parseFormatString(auth_rule, escape, pos).value_or("");
  if (fields[Format].empty()){
    return std::nullopt;
  }
  if(auth_rule[pos - 1] != ']'){
    LOG(ERROR) << "Expected ']' at the end of format string in rule: " << auth_rule << 
    " but got '" << auth_rule[pos - 1] << "' instead";
    return std::nullopt;
  }
  //This is an optional field, but if something is wrong we still have to bail
  std::optional<std::string> match_string = parseMatchString(auth_rule, escape, pos);
  if(!match_string.has_value()){
    return std::nullopt;
  }
  fields[Match] = match_string.value();
  //This is an optional field, but if something is wrong we have to bail
  std::optional<std::string> sed_string = parseSedString(auth_rule, pos);
  if (!sed_string.has_value()) {
    return std::nullopt;
  }
  fields[Sed] = sed_string.value();

  if(escape){
    LOG(ERROR) << "Unterminated backslash in rule: " << auth_rule;
    return std::nullopt;
  }

  //Parse \Q..\E in the match field (Java regex feature)
  std::optional<std::string> match_field_processed = 
    processJavaRegexLiterals(fields[Field::Match]);

  if (match_field_processed.has_value()) {
    fields[Match] = match_field_processed.value();
  } else {
    LOG(ERROR) << "Failed to process regex literals in match field: " << fields[Match];
    return std::nullopt;
  }
  return fields;
}

//Parse the number at the beginning of the [] in a rule ie [1:...]
std::optional<std::string> HadoopAuthToLocal::parseNumberString(std::string_view auth_rule, size_t& pos) const {
  std::string number;
  while (pos < auth_rule.length() && std::isdigit(auth_rule[pos], this->loc_)) {
    number += auth_rule[pos];
    ++pos;
  }
  if (number.empty()) {
    LOG(ERROR) << "Expected a number in rule: " << auth_rule;
    return std::nullopt;
  }
  return number;
}

//Parse the format string in a rule ie [...:$1@$0]
std::optional<std::string> HadoopAuthToLocal::parseFormatString(std::string_view auth_rule, bool& escape, size_t& pos) {
  if (pos >= auth_rule.length() || auth_rule[pos] != ':') {
    LOG(ERROR) << "Expected ':' before format string in rule: " << auth_rule;
    return std::nullopt;
  }
  ++pos; // Skip the ':'
  std::string format_string;
  

  while (pos < auth_rule.length()) {
    char current_char = auth_rule[pos];
    if (current_char == '\\' && !escape) {
      escape = true;
    } else {
      if (current_char == ']' && !escape) {
        break; // End of format string
      }
      format_string += current_char;
      escape = false;
    }
    ++pos;
  }
  if(pos >= auth_rule.length()) {
    LOG(ERROR) << "Unexpected end of rule";
    return std::nullopt;
  }
  if (auth_rule[pos] != ']') {
    LOG(ERROR) << "Expected ']' at the end of format string in rule: " << auth_rule;
    return std::nullopt;
  }
  ++pos; // Skip the ']'

  return format_string;
}

//Parse the match string, if it exists. This is the part in parentheses in a rule (hdfs@EXAMPLE.COM)
std::optional<std::string> HadoopAuthToLocal::parseMatchString(std::string_view auth_rule, bool& escape, size_t& pos){
  if (pos >= auth_rule.length() || auth_rule[pos] == 's') {
    return "";
  }
  if (auth_rule[pos] != '(' ){
    return std::nullopt;
  }
  ++pos; // Skip the '('
  std::string match_string;
  int paren_count = 1;

  while (pos < auth_rule.length() && paren_count > 0) {
    char current_char = auth_rule[pos];
    if (current_char == '\\' && !escape) {
      match_string += current_char;
      escape = true;
    } else {
      if (current_char == ')' && !escape) {
        --paren_count;
        if (paren_count > 0) {
          match_string += current_char;
        }
      } else if (current_char == '(' && !escape) {
        ++paren_count;
      } else {
        match_string += current_char;
        escape = false;
      }
    }
    ++pos;
  }

  if (paren_count != 0) {
    LOG(ERROR) << "Unmatched parentheses in rule: " << auth_rule;
    return std::nullopt;
  }

  return match_string;
}

//This grabs the rest of the string if it exists. If it doesn't start with 's',
//that means something has gone wrong.
std::optional<std::string> HadoopAuthToLocal::parseSedString(std::string_view auth_rule, size_t& pos){
  if (pos >= auth_rule.length()) {
    return ""; // Sed rule is optional
  }
  if (auth_rule[pos] != 's'){
    LOG(ERROR) << "Expected 's' at the start of sed rule in: " << auth_rule;
    return std::nullopt;
  }
  std::string sed_rule = std::string(auth_rule.substr(pos));
  return sed_rule;
}
//This takes a rule and initializes it. It will return an optional Rule
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

//Gets the number of fields in a principal. This is the number of distinct parts
//before the '@' ie foo/bar@EXAMPLE.COM has two fields
int HadoopAuthToLocal::numberOfFields(std::string_view principal) const{
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

//Returns all of the parts of the principal, including the realm.
//Importantly, the realm is appended to the front of the vector
//since it is field 0
std::vector<std::string> HadoopAuthToLocal::extractFields(std::string_view principal) const{
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

//Grab the realm from a principal
std::string HadoopAuthToLocal::getRealm(const std::string_view principal, size_t at_pos) const{
  if (at_pos == kAtPosDefault){
    at_pos = principal.find('@');
  }
  if(!checkPrincipal(principal, at_pos)){
    LOG(WARNING) << "Invalid principal format: " << principal;
    return "";
  }
  return std::string(principal.substr(at_pos + 1));
}

//This only proceeds to replacing the principal if it matches the (hdfs@EXAMPLE.COM) 
//regex. Otherwise, it does not replace anything. If there's no sed rule, we can return early
std::optional<std::string> HadoopAuthToLocal::replaceMatchingPrincipal(
  const Rule& rule, 
  const std::string& formatted_principal)
{
  //We can return early since we have no match or sed pattern
  if (rule.regexMatchString.empty() && !rule.sedRule.has_value()) {
    return formatted_principal;
  }

  std::regex_constants::match_flag_type regex_replace_flags = std::regex_constants::format_first_only;
  bool lowercase_output = false;
  //This check here makes sure that the regex isn't going to be catastrophically bad for performance.
  //We fork a process to check that the regex can actually finish matching the string
  std::optional<bool> is_match = try_match_regex(
    rule.regexMatch, 
    rule.sedRule,
    formatted_principal,
    500);

  if(!is_match.has_value()) {
    return std::nullopt;
  }
  if(!is_match.value()) {
    return std::nullopt;
  }

  //This means that we had a match string, but no sed rule. We can return early
  if(!rule.sedRule.has_value()){ 
    return formatted_principal;
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

//Checks to validate that the principal is in the correct format
bool HadoopAuthToLocal::checkPrincipal(std::string_view principal, size_t at_pos ) const{
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

  for(size_t idx=0; idx < principal.length(); idx++){
    if(std::isspace(principal[idx], this->loc_)){
      LOG(WARNING) << "Principal cannot contain whitespace characters: " << principal;
      return false;
    }
  }

  return true;
}

//This is something specific to hadoop. The result at the end is not allowed to contain
//either a '/' or '@' when the rule mechanism is set to Hadoop.
bool HadoopAuthToLocal::simplePatternCheck(std::string_view short_name) const{
  if(this->ruleMechanism_ == RuleMechanism::HADOOP) { 
    if (short_name.find_first_of("@/") != std::string::npos){ 
      LOG(WARNING) << "Short name cannot contain both '@' and '/' characters: " << short_name;
      return false;
    }
  }

  return true;
}

//If a rule hits DEFAULT and its realm matches the default realm,
//we return the first field in the principal.
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

//This formats the principal. if the rule is DEFAULT, we have to handle it separately
//if it's not, we just pass it along to format to create our format string
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

//This is where everything is called. This checks the principal against every possible rule
std::optional<std::string> HadoopAuthToLocal::transformPrincipal(
  const Rule& rule, 
  std::string_view principal,
  const std::vector<std::string>& fields) const
{
  if(!checkPrincipal(principal)){
    return std::nullopt;
  }
  std::string realm = getRealm(principal);
  if (rule.fmt == "DEFAULT" && realm == this->defaultRealm_) {
    if(fields.size() >= 2){
      return fields[1];
    }
    LOG(ERROR) << "Principal does not have enough fields for DEFAULT rule: " << principal;
    return std::nullopt;
  } 

  if (rule.fmt == "DEFAULT" && realm != this->defaultRealm_) {
    return std::nullopt;
  }

  std::optional<std::string> formattedShortRule = createFormattedPrincipal(rule, fields );
  if (!formattedShortRule.has_value()) {
    return std::nullopt;
  }
  
  //If there's no regex match string and no sed rule, we can return the formatted principal directly
  if (rule.regexMatchString.empty() && !rule.sedRule.has_value()) 
  {
    return formattedShortRule;
  }

  std::optional<std::string> output = replaceMatchingPrincipal(rule, formattedShortRule.value());
  
  if (output.has_value() && simplePatternCheck(output.value())) {
    return output;
  }
  return std::nullopt;

}

//This just walks through alll the rules, and the first one that matches is what we return
std::optional<std::string> HadoopAuthToLocal::matchPrincipalAgainstRules(
  std::string_view principal) const
{
  std::shared_lock<std::shared_mutex> lock(mutex_);
  
  if(this->rulesByFields_.empty()) {
    LOG(ERROR) << "No auth_to_local rules loaded from Hadoop configuration";
    return std::nullopt;
  }

  //Only check against rules that have a matching number of fields for the principal
  int num_fields = numberOfFields(principal);
  //This means something is wrong with the principal
  if(num_fields < 0){
    LOG(INFO) << "Principal '" << principal << "' is invalid";
    return std::nullopt;
  }
  std::vector<std::string> fields = extractFields(principal);

  //Check first to see if we have some rule that matches the number of fields
  auto rulesIt = rulesByFields_.find(num_fields);
  if (rulesIt != rulesByFields_.end()) {
    for(const Rule& rule : rulesIt->second){
      std::optional<std::string> new_principal = transformPrincipal(rule, principal, fields);
      if(new_principal.has_value()) {
        LOG(INFO) << "Transformed principal: " << principal << " to " << new_principal.value() << " using rule: " << rule.rule;
        return new_principal;
      }
    }
  }

  //Otherwise check the default rule (a zero field rule)
  auto defaultIt = rulesByFields_.find(0);
  if (defaultIt != rulesByFields_.end()) {
    for(const Rule& rule : defaultIt->second){
      //Only consider rules which are actually DEFAULT
      //There should ideally only be the one rule in this vector
      if (rule.fmt == "DEFAULT") {
        std::optional<std::string> new_principal = transformPrincipal(rule, principal, fields);
        if(new_principal.has_value()) {
          LOG(INFO) << "Transformed principal to DEFAULT: " << principal << " to " << new_principal.value() << " using rule: " << rule.rule;
          return new_principal;
        }
      }
    }
  }

  return std::nullopt;
}

} // namespace security
} // namespace kudu
