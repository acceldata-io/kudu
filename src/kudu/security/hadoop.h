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
#include <gtest/gtest_prod.h>
#include <krb5/krb5.h>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace kudu{
namespace security {
class HadoopAuthToLocal {

  static constexpr std::size_t kParseFields = 4;
  static constexpr std::size_t kAtPosDefault = -2;

  enum class RuleMechanism {HADOOP, MIT};

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
  std::string defaultRealm_ ;
  std::vector<Rule> rules_;
  RuleMechanism ruleMechanism_ = RuleMechanism::HADOOP;

  mutable std::shared_mutex mutex_;

  void setDefaultRealm(const std::string& realm);

  static bool checkPrincipal(std::string_view principal, size_t at_pos = kAtPosDefault);
  static int numberOfFields(std::string_view principal);
  static std::optional<Rule> initRule(const std::string& auth_rule);
  static std::optional<SedRule> parseSedRule(std::string_view sed_rule);
  static std::optional<std::array<std::string, kParseFields>> parseAuthToLocalRule(
    const std::string &rule);

  static std::optional<std::string> format(
    const std::string& fmt, 
    const std::vector<std::string>& values);

  static std::optional<std::string> processJavaRegexLiterals(std::string_view input);
  static std::optional<std::string> replaceMatchingPrincipal(
    const Rule& rule, 
    const std::string& formatted_principal);

  static std::optional<std::vector<Token>> tokenize(const std::string& fmt);
  static std::string escapeJavaRegexLiteral(std::string_view input);
  static std::string getRealm(std::string_view principal, size_t at_pos = kAtPosDefault);
  static std::vector<std::string> extractFields(std::string_view principal);
  
  bool loadConf(const std::string& filepath);
  bool matchNumberOfFields(const Rule &rule, std::string_view principal) const;
  bool setKrb5Context(krb5_context& ctx);
  bool setRules(std::istream& input);
  bool simplePatternCheck(std::string_view short_name) const;

  int fieldsMatch(const Rule &rule, std::string_view principal);

  std::optional<std::string> createFormattedPrincipal(
    const Rule& rule, 
    const std::vector<std::string>& principal_fields ) const;

  std::optional<std::string> defaultRule(
    const Rule& rule, 
    const std::string& principal, 
    std::string_view realm) const;

  std::optional<std::string> transformPrincipal(const Rule& rule, std::string_view principal) const;


  FRIEND_TEST(HadoopAuthToLocalTest, badFormatTest);
  FRIEND_TEST(HadoopAuthToLocalTest, badInitRulesTest);
  FRIEND_TEST(HadoopAuthToLocalTest, badLoadRulesTest);
  FRIEND_TEST(HadoopAuthToLocalTest, badParseAuthToLocalRuleTest);
  FRIEND_TEST(HadoopAuthToLocalTest, badSedRuleTest);
  FRIEND_TEST(HadoopAuthToLocalTest, checkPrincipalTest);
  FRIEND_TEST(HadoopAuthToLocalTest, formatTest);
  FRIEND_TEST(HadoopAuthToLocalTest, getRealmTest);
  FRIEND_TEST(HadoopAuthToLocalTest, initRuleTest);
  FRIEND_TEST(HadoopAuthToLocalTest, loadRulesTest);
  FRIEND_TEST(HadoopAuthToLocalTest, matchPrincipalAgainstAllRulesTest);
  FRIEND_TEST(HadoopAuthToLocalTest, numberOfFieldsTest);
  FRIEND_TEST(HadoopAuthToLocalTest, parseAuthToLocalRuleTest);
  FRIEND_TEST(HadoopAuthToLocalTest, ruleMechanismTest);
  FRIEND_TEST(HadoopAuthToLocalTest, sedRuleTest);
  FRIEND_TEST(HadoopAuthToLocalTest, threadSafeTest);
  FRIEND_TEST(HadoopAuthToLocalTest, transformPrincipalTest);
  FRIEND_TEST(HadoopAuthToLocalTest, negativeTransformPrincipalTest);

  public:
    //This constructor does not load rules, or set the default realm. Use init instead.
    HadoopAuthToLocal();
    //This should be the preferred way to initialize HadoopAuthToLocal
    static std::unique_ptr<HadoopAuthToLocal> init(const std::string& filepath, krb5_context& ctx);
    std::vector<std::string> getRules() const;
    std::optional<std::string> matchPrincipalAgainstRules(std::string_view principal) const;
};
} // namespace security
} // namespace kudu
