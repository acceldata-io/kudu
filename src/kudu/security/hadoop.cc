#include <algorithm>
#include <assert.h>
#include <vector>
#include <optional>
#include <hadoop.h>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>


HadoopAuthToLocal::HadoopAuthToLocal(const std::string& filepath, krb5_context& ctx) {


  defaultRealm = "ADSE.COM";
  setConf(filepath);
}
HadoopAuthToLocal::HadoopAuthToLocal(){

}
int HadoopAuthToLocal::setConf(const std::string& filepath) {
  boost::property_tree::ptree pt;
  try {
    boost::property_tree::read_xml(filepath, pt);
    std::ifstream file(filepath);
    if(file.good()){
      boost::property_tree::ptree tree;
      boost::property_tree::read_xml(filepath, tree);

      for (const auto &property : tree.get_child("configuration")){

        if(property.first == "property") {
          std::string name = property.second.get<std::string>("name", "");
          if (name == "hadoop.security.auth_to_local") {
            boost::split(this->coreSiteRules, property.second.get<std::string>("value", ""), boost::is_any_of("\n"));
          }
          if (this->coreSiteRules.size() > 0) {
            for (auto &rule : this->coreSiteRules) {
              boost::trim(rule);
              std::optional<Rule> r = initRule(rule);
              if (r.has_value()) {
                this->rules.push_back(r.value());
              } else {
                std::cerr << "Invalid rule: " << rule << "\n";
              }

            }
            return 0;
          }
        }
      }  
    }
  } catch (const boost::property_tree::xml_parser_error& e) {
    std::cerr << "Malformed XML\n";
    return -1;
  }

  return -1;
}


std::optional<std::vector<HadoopAuthToLocal::Token>> HadoopAuthToLocal::tokenize(const std::string &fmt) {
  std::vector<Token> tokens;
  tokens.reserve(fmt.length());
  if (fmt.empty()) {
    return std::nullopt;
  }

  if (fmt == "DEFAULT"){
    return std::nullopt;
  }
  std::size_t i = 0, end = fmt.length() ;
  while (i < end) {
    if (fmt[i] == '\\' && (i + 1) < end && fmt[i + 1] == '$') {
      
      i += 2;
      tokens.push_back(Token{.type = Token::Type::literal, .text = "$"});
    } else if (fmt[i] == '$' && (i + 1) < end && std::isdigit(fmt[i + 1])) {
      size_t start = i;
      i += 2;
      while (i < end && std::isdigit(fmt[i])) {
        i++;
      }
      tokens.push_back(Token{.type = Token::Type::placeholder,
                             .text = fmt.substr(start, i - start)});
    } else {
      size_t start = i;
      while (i < end &&
             !(fmt[i] == '$' && (i + 1 < end) && std::isdigit(fmt[i + 1])) &&
             !(fmt[i] == '\\' && (i + 1 < end) && fmt[i + 1] == '$')) {
        i++;
      }
      tokens.push_back(Token{.type = Token::Type::literal,
                             .text = fmt.substr(start, i - start)});
    }
  }
  return tokens;
}
std::optional<std::string> HadoopAuthToLocal::format(const std::string &fmt, const std::vector<std::string> &values) {
  std::string result;
  std::vector<Token> tokens = tokenize(fmt).value_or(std::vector<Token>{});
  for (const auto &token : tokens) {
    if (token.type == Token::Type::placeholder) {
      size_t idx = 0, pos = 1;
      while (pos < token.text.length() && std::isdigit(token.text[pos])) {
        idx = idx * 10 + (token.text[pos] - '0');
        pos++;
      }
      if (idx < values.size()) {
        result += values[idx];
      } else {
        return std::nullopt;
      }
    } else if (token.type == Token::Type::literal) {
      result.append(token.text);
    }
  }
  return result;
}

std::string HadoopAuthToLocal::escapeJavaRegexLiteral(const std::string& input){
  static const boost::regex  re(R"([.^$|()\\[\]{}*+?])");
  return boost::regex_replace(input, re, R"(\$&)");
}

std::string HadoopAuthToLocal::processJavaRegexLiterals(const std::string& input) {
   std::string output;
    size_t i = 0;
    while (i < input.size()) {
        if (input.substr(i, 2) == "\\Q") {
            i += 2;
            size_t end = input.find("\\E", i);
            if (end == std::string::npos) {
                throw std::runtime_error("Unterminated \\Q in regex literal");
                break;
            } else {
                output += escapeJavaRegexLiteral(input.substr(i, end - i));
                i = end + 2;
            }
        } else {
            output += input[i++];
        }
    }
    return output;
}

std::optional<HadoopAuthToLocal::SedRule> HadoopAuthToLocal::parseSedRule(const std::string& sedRule){
  if (sedRule.empty()) {
      return std::nullopt;
    }
    if (sedRule.size() < 3 || sedRule[0] != 's') {
      std::cerr << "Rule must start with 's' and a delimiter\n";
      std::cerr << "It is: '" << sedRule << "'\n";
      return std::nullopt;
    }
    char delimiter = sedRule[1];
    std::string rule = sedRule.substr(2); //skip the s + delimiter
    size_t pos = 0; 
    std::string part[2];
    int part_idx = 0;
    bool escape = false;
    
    if (std::isalnum(delimiter) || delimiter == '\\' || delimiter == ' ') {
      std::cerr << "Invalid delimiter: '" << delimiter << "'\n";
      return std::nullopt;
    }

    while (pos < rule.size() && part_idx < 2) {
        char c = rule[pos];
        if (escape) {
            part[part_idx] += c;
            escape = false;
        } else if (c == '\\') {
            escape = true;
        } else if (c == delimiter) {
            ++part_idx;
        } else {
            part[part_idx] += c;
        }
        ++pos;
    }

    if (part_idx < 2) {
      std::cerr << "Malformed sed rule: missing delimiters\n";
      return std::nullopt;
    }

    std::string flags;
    if (pos <= rule.size()) {
        flags = rule.substr(pos);
    }

    if (part[0].empty()) {
      std::cerr << "Pattern cannot be empty\n";
      return std::nullopt;
    }
    if (escape) {
      std::cerr << "Trailing backslash in sed rule\n";
      return std::nullopt;
    }
    return SedRule{part[0], part[1], flags};
}

std::optional<std::array<std::string, HadoopAuthToLocal::PARSE_FIELDS>> HadoopAuthToLocal::parseAuthToLocalRule(const std::string& rule){
  if(rule.empty()) {
    return std::nullopt;
  }
  enum State {START, NUMBER, FORMAT, REGEX};
  State state = START;
  std::string prefix = "RULE:[";
  size_t pos = prefix.length();
  std::string number="", format="", regex_match="", sed_rule="";
  std::string auth_rule = rule;
  boost::trim(auth_rule);


  if(auth_rule == "DEFAULT"){
    return std::array<std::string, PARSE_FIELDS> {"0", "DEFAULT", "", ""};
  }
  else if(auth_rule.rfind(prefix, 0) != 0 ){
    std::cerr << "Invalid rule format: " << auth_rule << "\n";
    return std::nullopt;
  }
  
  state = NUMBER;

  while(pos < auth_rule.length() && isdigit(auth_rule[pos])){
    number += auth_rule[pos];
    pos++;
  }
  if (pos >= auth_rule.length() || (state == NUMBER && auth_rule[pos] != ':')) {
    std::cerr << "Expected ':' at char " << pos << ", got " << auth_rule[pos] << "instead\n";
    return std::nullopt;
  }
  pos++;

  state = FORMAT;
  bool escape = false;
  while (pos < auth_rule.length() && state == FORMAT) {
    char c = auth_rule[pos++];
    if (escape) {
      format += c;
      escape = false;
    } else if (c == '\\') {
      escape = true;
    } else if (c == ']') {
      state = REGEX;
      break;
    } else {
      format += c;
    }
  }

  if(state == REGEX && auth_rule[pos-1] != ']'){
    std::cerr << "Expected ']' at char " << pos << ", got '" << auth_rule[pos-1] << "' instead \n";
    return std::nullopt;
  }

  if(pos>= auth_rule.length() || auth_rule[pos] != '('){

    std::cerr << "Expected '(' at char " << pos+1 << " in "<< auth_rule << "\n";
    std::cerr << "Got " << auth_rule[pos] << " instead\n";
    return std::nullopt;
  }

  pos++;
  escape = false;
  while (pos < auth_rule.length()) {
    char c = auth_rule[pos++];
    if (escape){
      regex_match += c;
      escape = false;
    }
    else if (c == '\\'){
      regex_match += c;
      escape = true;
    } else if (!escape && c == ')'){
      break;
    } else {
      regex_match += c;
    }
  }
  regex_match = processJavaRegexLiterals(regex_match);
  if (pos < auth_rule.length()){
    sed_rule = auth_rule.substr(pos);
  }

  if (!sed_rule.empty()) {
    sed_rule = processJavaRegexLiterals(sed_rule);
  }

  boost::trim(number);
  boost::trim(format);
  boost::trim(regex_match);
  boost::trim(sed_rule);
  return std::array<std::string, HadoopAuthToLocal::PARSE_FIELDS>{ number, format, regex_match, sed_rule };
}

std::optional<HadoopAuthToLocal::Rule> HadoopAuthToLocal::initRule(const std::string &auth_rule){
  if (auth_rule.empty()){
    return std::nullopt;
  }
  std::string trimmed = auth_rule;
  boost::trim(trimmed);
  auto auth_to_local = parseAuthToLocalRule(trimmed);

  if(auth_to_local.has_value()){
    auto [num_fields, format, regex_match_str, sed_rule] = auth_to_local.value();
    if (format != "DEFAULT" && (num_fields.empty() || format.empty() || regex_match_str.empty())) {
      std::cerr << "Invalid rule format: " << auth_rule << "\n";
      return std::nullopt;
    }
    Rule rule = 
      {
        .numberOfFields = std::stoi(num_fields),
        .fmt = format,
        .rule = auth_rule,
        .regexMatchString = regex_match_str,
        .regexMatch = boost::regex(regex_match_str, boost::regex::extended),
        .sedRule = parseSedRule(sed_rule),
        
      };
    return rule;
  }
  
  return std::nullopt;
}

int HadoopAuthToLocal::numberOfFields(const std::string& principal){
  size_t at_pos = principal.find("@");
  if (checkPrincipal(principal, at_pos)){
    return -1;
  }
  std::string principal_without_realm = principal.substr(0, at_pos);
  std::string::difference_type n = std::count(principal_without_realm.begin(), principal_without_realm.end(), '/');
  int count = static_cast<int>(n);
  // Count is the number of slashes, but we want the actual number of fields separated by the slashes, so one extra.
  return count + 1;
}

std::vector<std::string> HadoopAuthToLocal::extractFields(const std::string &principal){
  size_t at_pos = principal.find("@");
  if(!checkPrincipal(principal, at_pos)){
    return std::vector<std::string>{};
  }
  std::vector<std::string> fields;
  boost::algorithm::split(fields, principal.substr(0, at_pos), boost::is_any_of("/"));

  fields.insert(fields.begin(),  principal.substr(at_pos + 1) );
  return fields;
}

std::string HadoopAuthToLocal::getRealm(const std::string& principal, size_t at_pos){
  if (at_pos == at_pos_default){
    at_pos = principal.find("@");
  }
  if(!checkPrincipal(principal, at_pos)){
    return "";
  }
  return principal.substr(at_pos);
}

int HadoopAuthToLocal::matchNumberOfFields(const Rule& rule, const std::string& principal){
  if(rule.fmt == "DEFAULT" && getRealm(principal) == this->defaultRealm) {
    return 0;
  }
  int fields = numberOfFields(principal);
  if(rule.numberOfFields == fields) {
    return 0;
  }
  return -1;
}

int HadoopAuthToLocal::replaceMatchingPrincipal(const Rule& rule, const std::string& formattedPrincipal, std::string& output){
  if (!rule.sedRule.has_value()){
    output = formattedPrincipal;
    return 0;
  }

  boost::regex_constants::match_flags regex_replace_flags = boost::regex_constants::format_first_only;
  boost::regex_constants::syntax_option_type regex_opts = boost::regex_constants::ECMAScript;
  bool lowercase_output = false;

  if(!boost::regex_match(formattedPrincipal, rule.regexMatch)){
    return -1;
  }
  assert(rule.sedRule.has_value());
  if (auto sed = rule.sedRule){
    if(!sed->flags.empty()){
      if(sed->flags.find("g") != std::string::npos){
        regex_replace_flags = boost::regex_constants::match_all;
      }
      //This is a hadoop specific extension.
      if(sed->flags.find("L") != std::string::npos){
        lowercase_output = true;
      }
    }
  }
  
  boost::regex match = boost::regex(rule.sedRule.value().pattern, regex_opts);
  output = boost::regex_replace(formattedPrincipal, match, rule.sedRule.value().replacement, regex_replace_flags);
  if(lowercase_output) {
    std::transform(output.begin(), output.end(), output.begin(), ::tolower);
  }
  return 0;
}

bool HadoopAuthToLocal::checkPrincipal(std::string_view principal, size_t at_pos ){
  if (at_pos == at_pos_default ){
    at_pos = principal.find("@");
  }
  else if (at_pos == std::string::npos){
    return false;
  }
  return (principal.empty() || at_pos == std::string::npos || !principal.substr(0,at_pos).empty());
}

std::optional<std::string> HadoopAuthToLocal::defaultRule(const Rule& rule, const std::string& principal, const std::string& realm){
  if (rule.fmt == "DEFAULT" && realm == this->defaultRealm) {
    std::vector<std::string> fields = extractFields(principal);
    if(fields.size() > 1){
      return fields[1];
    }
  }
  return std::nullopt;
}

std::optional<std::string> HadoopAuthToLocal::createFormattedPrincipal(const Rule& rule, const std::vector<std::string>& fields){
  std::optional<std::string> result = std::nullopt;
  if (fields.size() < 2) {
    //log here
    return std::nullopt;
  }
  else if (rule.fmt == "DEFAULT") {
    return defaultRule(rule, fields[1], fields[0]);
  }
  else {
    result = format(rule.fmt, fields);
  }
  return result;
}

int HadoopAuthToLocal::transformPrincipal(const Rule& rule, const std::string& principal, std::string&output){
  if(!checkPrincipal(principal)){
    output = "";
    return -1;
  }
  std::string realm = getRealm(principal);
  std::string shortName = "";
  //Check how this works in krb5
  if (rule.fmt == "DEFAULT" && realm == this->defaultRealm) {
    std::vector<std::string> fields = extractFields(principal);
    if(fields.size() > 1){
      output = fields[1];
      return 0;
    }
    return -1;
  }
  if (!matchNumberOfFields(rule,principal)){
    return -1;
  }
  std::vector<std::string> fields = extractFields(principal);
  std::optional<std::string> formattedShortRule = createFormattedPrincipal(rule, fields );
  if (!formattedShortRule.has_value()) {
    output = "";
    return -1;
  }
  if(replaceMatchingPrincipal(rule, formattedShortRule.value(), output) != 0){
      output = "";
      return -1;
    }
  return 0;

  output = "";
  return -1;
}

int HadoopAuthToLocal::matchPrincipalAgainstRules(const std::string &principal, std::string &output){
  for (const auto &rule : rules) {
    output.clear();
    if (transformPrincipal(rule, principal, output) == 0) {
      return 0;
    }
  }

  return -1;
}
