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
#include <locale>
#include <map>
#include <mutex>
#include <list>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <string>
#include <vector>
namespace kudu{
namespace security {

class PrincipalLRUCache {
private:
  size_t max_size_;
  mutable std::mutex mutex_;
  std::list<std::string> list_;
  std::unordered_map<
    std::string,
    std::pair<std::optional<std::string>, std::list<std::string>::iterator>
  > map_;
public:
  explicit PrincipalLRUCache(size_t max_size) : max_size_(max_size) {}
  std::optional<std::optional<std::string>> get(const std::string& key){
    std::lock_guard<std::mutex> lock(mutex_);
    auto iterator = map_.find(key);
    if (iterator == map_.end()) {
      return std::nullopt;
    }
    list_.splice(list_.begin(), list_, iterator->second.second);
    return iterator->second.first;
  }
  void put(const std::string& key, const std::optional<std::string>& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto iterator = map_.find(key);
    if (iterator != map_.end()) {
      iterator->second.first = value;
      list_.splice(list_.begin(), list_, iterator->second.second);
      return;
    }
    list_.push_front(key);
    map_[key] = {value, list_.begin()};
    if (map_.size() > max_size_) {
      auto lru = list_.end();
      --lru;
      map_.erase(*lru);
      list_.pop_back();
    }
  }
};

class HadoopAuthToLocal {

  static constexpr std::size_t kParseFields = 4;
  static constexpr std::size_t kAtPosDefault = -2;
  static constexpr uint kMaxStuckThreads = 4;

  enum class RuleMechanism {HADOOP, MIT};
  enum class RegexResult {
    Match,
    NoMatch,
    Error,
    Timeout,
  };


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

  const std::locale loc_ = std::locale("");
  std::vector<std::string> coreSiteRules_;
  std::string defaultRealm_ ;
  std::unordered_map<int, std::vector<Rule>> rulesByFields_;
  RuleMechanism ruleMechanism_ = RuleMechanism::HADOOP;
  PrincipalLRUCache cache_{1024};

  mutable std::shared_mutex mutex_;

  void setDefaultRealm(const std::string& realm);

  bool checkPrincipal(std::string_view principal, size_t at_pos = kAtPosDefault) const;
  int numberOfFields(std::string_view principal) const;
  std::optional<Rule> initRule(const std::string& auth_rule);
  RegexResult tryMatchRegex(
    const std::regex& reg, 
    const std::optional<SedRule>& sed_match, 
    std::string_view match_string, 
    int milliseconds);
  static std::optional<SedRule> parseSedRule(std::string_view sed_rule) noexcept;
  static std::optional<std::string> parseSedFlags(std::string_view flag, char delimiter) noexcept;
  std::optional<std::array<std::string, kParseFields>> parseAuthToLocalRule(
    std::string_view rule);

  std::optional<std::string> parseNumberString(
    std::string_view auth_rule, 
    size_t& pos) const; 
    
  static std::optional<std::string> parseFormatString(
    std::string_view auth_rule,
    bool& escape,
    size_t& pos);
  static std::optional<std::string> parseMatchString(
    std::string_view auth_rule, 
    bool& escape,
    size_t& pos);
  static std::optional<std::string> parseSedString(std::string_view auth_rule, size_t& pos);
   

  std::optional<std::string> format(
    const std::string& fmt, 
    const std::vector<std::string>& values) const;

  static std::optional<std::string> processJavaRegexLiterals(std::string_view input);
  std::optional<std::string> replaceMatchingPrincipal(
    const Rule& rule, 
    const std::string& formatted_principal);

  static std::string escapeJavaRegexLiteral(std::string_view input);
  std::string getRealm(std::string_view principal, size_t at_pos = kAtPosDefault) const;
  std::vector<std::string> extractFields(std::string_view principal) const;
  
  bool loadConf(const std::string& filepath);
  bool setKrb5Context(krb5_context& ctx);
  bool setRules(std::istream& input);
  bool simplePatternCheck(std::string_view short_name) const;

  std::optional<std::string> createFormattedPrincipal(
    const Rule& rule, 
    const std::vector<std::string>& principal_fields ) const;

  std::optional<std::string> defaultRule(
    const Rule& rule, 
    const std::string& principal, 
    std::string_view realm) const;

  std::optional<std::string> transformPrincipal(
    const Rule& rule,
    std::string_view principal, 
    const std::vector<std::string>& fields,
    std::string_view realm);


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
  FRIEND_TEST(HadoopAuthToLocalTest, testRegexMatch);
  FRIEND_TEST(HadoopAuthToLocalTest, threadSafeTest);
  FRIEND_TEST(HadoopAuthToLocalTest, transformPrincipalTest);
  FRIEND_TEST(HadoopAuthToLocalTest, negativeTransformPrincipalTest);

  public:
    
    //This constructor does not load rules, or set the default realm. Use init instead.
    HadoopAuthToLocal();
    //This should be the preferred way to initialize HadoopAuthToLocal
    static std::unique_ptr<HadoopAuthToLocal> init(const std::string& filepath, krb5_context& ctx);
    std::vector<std::string> getRules() const;
    std::optional<std::string> matchPrincipalAgainstRules(std::string_view principal);
};

} // namespace security
} // namespace kudu
