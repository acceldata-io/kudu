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

#include <krb5/krb5.h>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <string>
#include <vector>


class HadoopAuthToLocal {

  static constexpr std::size_t kParseFields = 4;
  static constexpr std::size_t kAtPosDefault = -2;
  struct SedRule {
    std::string pattern;
    std::string replacement;
    std::string flags;
    std::regex compiled_pattern;
  };
  struct Rule {
    int numberOfFields;
    std::string fmt;
    std::string rule;
    std::string regexMatchString;
    std::regex regexMatch;
    std::optional<SedRule> sedRule;
  };
  struct Token {
    enum class Type {placeholder, literal};
    Type type;
    std::string text;
  };
  using Token = HadoopAuthToLocal::Token;

  std::vector<std::string> coreSiteRules_;
  std::vector<Rule> rules_;
  std::string defaultRealm_ = "";
  mutable std::shared_mutex mutex_;


  static std::optional<Rule> initRule(const std::string& auth_rule);
  static std::optional<SedRule> parseSedRule(const std::string& sed_rule);
  static int numberOfFields(const std::string& principal);
  int fieldsMatch(const Rule &rule, const std::string& principal);
  bool matchNumberOfFields(const Rule &rule, const std::string&principal);
  static std::optional<std::string> replaceMatchingPrincipal(const Rule& rule, const std::string& formatted_principal);
  std::optional<std::string> transformPrincipal(const Rule& rule, const std::string& principal);
  static std::optional<std::array<std::string, kParseFields>> parseAuthToLocalRule(const std::string &auth_rule);
  

  std::optional<std::string> createFormattedPrincipal(const Rule& rule, const std::vector<std::string>& principal_fields );
  std::optional<std::string> defaultRule(const Rule& rule, const std::string& principal, const std::string& realm);

  static bool checkPrincipal(std::string_view principal, size_t at_pos = kAtPosDefault);
  static std::string getRealm(const std::string& principal, size_t at_pos = kAtPosDefault);
  static std::string processJavaRegexLiterals(const std::string& input);
  static std::string escapeJavaRegexLiteral(const std::string& input);

  static std::optional<std::string> format(const std::string& fmt, const std::vector<std::string>& values);
  static std::optional<std::vector<Token>> tokenize(const std::string& fmt);

  static std::vector<std::string> extractFields(const std::string& principal);

  public:
    HadoopAuthToLocal(const std::string& filepath, krb5_context& ctx);
    int setConf(const std::string& filepath);
    int setKrb5Context(krb5_context& ctx);
    void setDefaultRealm(const std::string& realm);
    std::optional<std::string> matchPrincipalAgainstRules(const std::string& principal);
    const std::vector<std::string>& getRules();
};
