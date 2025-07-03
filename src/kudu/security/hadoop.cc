#include <cassert>
#include <cstring>
#include <vector>
#include <optional>
#include <locale>
#include <climits>
#include "hadoop.h"
#include <shared_mutex>
#include <string>
#include <regex>
#include <glog/logging.h>

#include "kudu/gutil/strings/split.h"
#include "kudu/gutil/strings/strip.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>

namespace kudu {
namespace security {
HadoopAuthToLocal::HadoopAuthToLocal(const std::string& filepath, krb5_context& ctx) {
  setConf(filepath);
  setKrb5Context(ctx);
}

int HadoopAuthToLocal::setKrb5Context(krb5_context& ctx){
  std::unique_lock<std::shared_mutex> lock(mutex_);
  char *realm;
  krb5_error_code err = krb5_get_default_realm(ctx, &realm);
  if(err){
    LOG(ERROR) << "Failed to get default realm from krb5 context: " << err << "\n";
    return -1;
  }
  defaultRealm_ = std::string(realm);
  StripWhiteSpace(&defaultRealm_);
  krb5_free_default_realm(ctx, realm);
  return 0;

}

int HadoopAuthToLocal::setConf(const std::string& filepath) {
  std::unique_lock<std::shared_mutex> lock(mutex_);

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

  boost::property_tree::ptree tree;
  try {
      boost::property_tree::read_xml(canonical_path, tree);
  } catch (const boost::property_tree::xml_parser_error& e) {
     LOG(ERROR) << "Malformed XML when loading " << filepath << " which resolves to " << canonical_path << " \n";
    return -1;
  }
  for (const auto &property : tree.get_child("configuration")){

    if(property.first == "property") {
      std::string name = property.second.get<std::string>("name", "");
      if (name == "hadoop.security.auth_to_local") {
        this->coreSiteRules_ = strings::Split(property.second.get<std::string>("value",""),"\n", strings::SkipWhitespace());
      }
      if (this->coreSiteRules_.size() > 0) {
        for (auto &rule : this->coreSiteRules_) {
          StripWhiteSpace(&rule);
          std::optional<Rule> new_rule = initRule(rule);
          if (new_rule.has_value()) {
            this->rules_.push_back(new_rule.value());
          } else {
            LOG(ERROR) << "Invalid rule: " << rule << "\n";
          }
        }
        return 0;
      }  
    }
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
    if (fmt[idx] == '\\' && (idx + 1) < end && fmt[idx + 1] == '$') {
      idx += 2;
      tokens.push_back(Token{.type = Token::Type::literal, .text = "$"});
    } else if (fmt[idx] == '$' && (idx + 1) < end && std::isdigit(fmt[idx + 1], loc)) {
      size_t start = idx;
      idx += 2;
      while (idx < end && std::isdigit(fmt[idx], loc)) {
        idx++;
      }
      tokens.push_back(Token{.type = Token::Type::placeholder,
                             .text = fmt.substr(start, idx - start)});
    } else {
      size_t start = idx;
      while (idx < end &&
              (fmt[idx] != '$' || (idx + 1 >= end) ) &&
              (fmt[idx] != '\\' || (idx + 1 >= end) || fmt[idx + 1] != '$')){
        idx++;
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
        pos++;
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
  static const std::regex  reg(R"([.^$|()\\[\]{}*+?])");
  return std::regex_replace(input, reg, R"(\$&)");
}

std::string HadoopAuthToLocal::processJavaRegexLiterals(const std::string& input) {
   std::string output;
    size_t idx = 0;
    while (idx < input.size()) {
        if (input.substr(idx, 2) == "\\Q") {
            idx += 2;
            size_t end = input.find("\\E", idx);
            if (end == std::string::npos) {
                LOG(ERROR) << "Unterminated \\Q in regex literal " << input << "\n";
                return input;
            } 
            output += escapeJavaRegexLiteral(input.substr(idx, end - idx));
            idx = end + 2;
        } else {
            output += input[idx++];
        }
    }
    return output;
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
  char delimiter = sed_rule[1];
  std::string rule = sed_rule.substr(2); //skip the s + delimiter
  size_t pos = 0; 
  constexpr size_t max_size = 128;
  std::string part[2];
  int part_idx = 0;
  bool escape = false;
  std::regex match_regex;
    
  if (std::isalnum(delimiter, loc) || delimiter == '\\' || delimiter == ' ' || delimiter == '@') {
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
  if (pos <= rule.size()) {
    flags = rule.substr(pos);
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
  std::string prefix = "RULE:[";
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
    pos++;
  }
  if (pos >= auth_rule.length() || auth_rule[pos] != ':') {
    LOG(ERROR) << "Expected ':' at char " << pos << ", got " << auth_rule[pos] << "instead\n";
    return std::nullopt;
  }
  pos++;

  bool escape = false;
  while (pos < auth_rule.length() ) {
    char current_char = auth_rule[pos++];
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

  if(auth_rule[pos-1] != ']'){
    LOG(ERROR) << "Expected ']' at char " << pos << ", got '" << auth_rule[pos-1] << "' instead \n";
    return std::nullopt;
  }

  if(pos>= auth_rule.length() || auth_rule[pos] != '('){

    LOG(ERROR) << "Expected '(' at char " << pos+1 << " in "<< auth_rule << "\n";
    LOG(ERROR) << "Got " << auth_rule[pos] << " instead\n";
    return std::nullopt;
  }

  pos++;
  escape = false;
  while (pos < auth_rule.length()) {
    char current_char = auth_rule[pos++];
    if (escape){
      regex_match += current_char;
      escape = false;
    }
    else if (current_char == '\\'){
      regex_match += current_char;
      escape = true;
    } else if (!escape && current_char == ')'){
      break;
    } else {
      regex_match += current_char;
    }
  }
  regex_match = processJavaRegexLiterals(regex_match);
  if (pos < auth_rule.length()){
    sed_rule = auth_rule.substr(pos);
  }

  if (!sed_rule.empty()) {
    sed_rule = processJavaRegexLiterals(sed_rule);
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
  return principal.substr(at_pos);
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
  assert(rule.sedRule.has_value());
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
  
  std::string output = std::regex_replace(formatted_principal, rule.sedRule.value().compiled_pattern, rule.sedRule.value().replacement, regex_replace_flags);
  if(lowercase_output) {
    std::transform(output.begin(), output.end(), output.begin(), ::tolower);
  }
  return output;
}

bool HadoopAuthToLocal::checkPrincipal(std::string_view principal, size_t at_pos ){
  if (at_pos == kAtPosDefault ){
    at_pos = principal.find('@');
  }
  else if (at_pos == std::string::npos){
    return false;
  }
  return !principal.empty() && at_pos != std::string::npos && !principal.substr(0,at_pos).empty();
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
  //Check how this works in krb5
  if (rule.fmt == "DEFAULT" && realm == this->defaultRealm_) {
    std::vector<std::string> fields = extractFields(principal);
    if(fields.size() > 1){
      return fields[1];
      
    }
    LOG(ERROR) << "Principal does not have enough fields for DEFAULT rule: " << principal << "\n";
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
