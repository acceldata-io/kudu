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

#pragma once

#include <vector>
#include <string>
#include <optional>
#include <krb5/krb5.h>
#include <boost/regex.hpp>


class HadoopAuthToLocal {

  static constexpr std::size_t PARSE_FIELDS = 4;
  static constexpr std::size_t at_pos_default = -2;
  struct SedRule {
    std::string pattern;
    std::string replacement;
    std::string flags;
  };
  struct Rule {
    int numberOfFields;
    std::string fmt;
    std::string rule;
    std::string regexMatchString;
    boost::regex regexMatch;
    std::optional<SedRule> sedRule;
  };
  struct Token {
    enum class Type {placeholder, literal};
    Type type;
    std::string text;
  };
  using Token = HadoopAuthToLocal::Token;

  std::vector<std::string> coreSiteRules;
  std::vector<Rule> rules;
  std::string defaultRealm = "";



  std::optional<Rule> initRule(const std::string& auth_rule);
  std::optional<SedRule> parseSedRule(const std::string&sedRule);
  int numberOfFields(const std::string& principal);
  int fieldsMatch(const Rule &rule, const std::string& principal);
  int matchNumberOfFields(const Rule &rule, const std::string&principal);
  int replaceMatchingPrincipal(const Rule& rule, const std::string& formattedPrincipal, std::string& output);
  int transformPrincipal(const Rule& rule, const std::string& principal, std::string& output);
  std::optional<std::array<std::string, PARSE_FIELDS>> parseAuthToLocalRule(const std::string &auth_rule);
  

  std::optional<std::string> createFormattedPrincipal(const Rule& rule, const std::vector<std::string>& principal );
  std::optional<std::string> defaultRule(const Rule& rule, const std::string& principal, const std::string& realm);
  int shortNameMatchesRule(const Rule& rule, const std::string modifiedPrincipal);

  bool checkPrincipal(std::string_view principal, size_t at_pos = at_pos_default);
  std::string getRealm(const std::string& principal, size_t at_pos = at_pos_default);
  std::string processJavaRegexLiterals(const std::string& input);
  std::string escapeJavaRegexLiteral(const std::string& input);

  std::optional<std::string> format(const std::string& fmt, const std::vector<std::string>& fields);
  std::optional<std::vector<Token>> tokenize(const std::string& fmt);

  std::vector<std::string> extractFields(const std::string& principal);

  public:
    HadoopAuthToLocal();
    HadoopAuthToLocal(const std::string& filepath, krb5_context& ctx);
    int setConf(const std::string& coreSite);
    int setKrb5Context(krb5_context& ctx);
    int matchPrincipalAgainstRules(const std::string& principal, std::string& output);
    const std::vector<std::string>& getRules();
};
