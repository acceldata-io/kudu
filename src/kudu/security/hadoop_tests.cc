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


#include <gtest/gtest.h>
#include "hadoop.h"

namespace kudu {
namespace security {


TEST(HadoopAuthToLocalTest, sedRuleTest) {
  std::string sed_rule = "s/@.//L/g";
  auto rule = HadoopAuthToLocal::parseSedRule(sed_rule);
  ASSERT_TRUE(rule.has_value());
  EXPECT_EQ(rule->pattern, "@.");
  EXPECT_EQ(rule->replacement, "");
  EXPECT_EQ(rule->flags, "Lg");
  EXPECT_NO_THROW(std::regex(rule->pattern));

  sed_rule = "s|@.||L|g";
  rule = HadoopAuthToLocal::parseSedRule(sed_rule);
  ASSERT_TRUE(rule.has_value());
  EXPECT_EQ(rule->pattern, "@.");
  EXPECT_EQ(rule->replacement, "");
  EXPECT_EQ(rule->flags, "Lg");
  EXPECT_NO_THROW(std::regex(rule->pattern));


}

TEST(HadoopAuthToLocalTest, badSedRuleTest) {
  std::string sed_rule = "r/@.//L/g";
  auto rule = HadoopAuthToLocal::parseSedRule("r/@.//L/g");
  ASSERT_FALSE(rule.has_value());

  rule = HadoopAuthToLocal::parseSedRule(R"(s/\//)");
  ASSERT_FALSE(rule.has_value());

  rule = HadoopAuthToLocal::parseSedRule("s|@.//L");
  ASSERT_FALSE(rule.has_value());

  ASSERT_FALSE(HadoopAuthToLocal::parseSedRule("").has_value());

  rule = HadoopAuthToLocal::parseSedRule("s/@.//L/gL");
}

TEST(HadoopAuthToLocalTest, parseAuthToLocalRuleTest){
  std::string rule = "RULE:[2:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/spark/ ";
  auto parsed_rule = HadoopAuthToLocal::parseAuthToLocalRule(rule);
  ASSERT_TRUE(parsed_rule.has_value());
  EXPECT_EQ(parsed_rule->size(), HadoopAuthToLocal::kParseFields);
  EXPECT_EQ(parsed_rule->at(0), "2");
  EXPECT_EQ(parsed_rule->at(1), "$1@$0");
  EXPECT_EQ(parsed_rule->at(2), "spark-rangerkerberos@EXAMPLE.COM");
  EXPECT_EQ(parsed_rule->at(3), "s/.*/spark/");

  parsed_rule = HadoopAuthToLocal::parseAuthToLocalRule(R"(RULE:[2:$1@$0](.*@\QCOMPANY.PRI\E$)s/@\QCOMPANY.PRI\E$//)");
  EXPECT_EQ(parsed_rule->size(), HadoopAuthToLocal::kParseFields);
  EXPECT_EQ(parsed_rule->size(), HadoopAuthToLocal::kParseFields);
  //R"(RULE:[2:$1@$0](.*@\QCOMPANY.PRI\E$)s/@\QCOMPANY.PRI\E$//)")
  //"mzeoli/somehost@COMPANY.PRI"
  //mzeoli
}

} // namespace security
} // namespace kudu
