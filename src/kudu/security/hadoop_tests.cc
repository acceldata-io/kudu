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
#include <gtest/gtest.h>
#include <string>
#include "hadoop.h"

namespace kudu {
namespace security {


TEST(HadoopAuthToLocalTest, sedRuleTest) {
  struct TestCase {
    std::string input;
    std::array<std::string, 3> expected;
  };
  std::vector<TestCase> test_cases = {
    {
      .input = "s/@.*//L/g",
      .expected = {"@.*", "", "Lg"},
    },
    {
      .input = "s|@.+||g|L",
      .expected = {"@.+", "", "gL"},
    },
    {
      .input = "s/@.//L",
      .expected = {"@.", "", "L"},
    },
    {
      .input = "s|@.||L",
      .expected = {"@.", "", "L"},
    },
    {
      .input = "s/.*/yarn-ats/g",
      .expected = {".*", "yarn-ats", "g"},
    },
    {
      .input = R"(s/\\/b/)",
      .expected = {"\\", "b", ""},
    },
    {
      .input = R"(s/\\$/$/g)",
      .expected = {"\\\\$", "$", "g"},
    },
  };
  std::optional<HadoopAuthToLocal::SedRule> rule;
  for (const auto &rule_str : test_cases) {
    rule = HadoopAuthToLocal::parseSedRule(rule_str.input);
    ASSERT_TRUE(rule.has_value()) << "Failed to parse sed rule: " << rule_str.input;
    EXPECT_EQ(rule->pattern, rule_str.expected[0]) << "Unexpected failure in " << rule_str.input;
    EXPECT_EQ(rule->replacement, rule_str.expected[1]);
    EXPECT_EQ(rule->flags, rule_str.expected[2]);
    EXPECT_NO_THROW(std::regex(rule->pattern));
  }

}

TEST(HadoopAuthToLocalTest, badSedRuleTest) {
  std::vector<std::string> input = {"r/@.//L/g",R"(s/\//)", "s|@.//L", "s/@.//L/gL", "  ", };
  std::optional<HadoopAuthToLocal::SedRule> rule;
  for(auto &rule_str : input) {
    rule = HadoopAuthToLocal::parseSedRule(rule_str);
    ASSERT_FALSE(rule.has_value()) << "Rule " << rule_str << " succeeded when it shouldn't have";
  }

}

TEST(HadoopAuthToLocalTest, parseAuthToLocalRuleTest){
  struct TestCase {
    std::string input;
    std::array<std::string, 4> expected;
  };
  std::vector<TestCase> test_cases = {
    {
      .input = "    RULE:[1:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/spark/    ",
      .expected = {"1", "$1@$0", "spark-rangerkerberos@EXAMPLE.COM", "s/.*/spark/"},
    },
    {
      .input = R"(RULE:[2:$1-$2@$0](.*@\QCOMPANY.PRI\E$)s/@\QCOMPANY.PRI\E$//)",
      .expected = {"2", "$1-$2@$0", ".*@COMPANY\\.PRI$", "s/@COMPANY\\.PRI$//"},
    },
    {
      .input = " RULE:[2:$1@$0](hue@EXAMPLE.COM)s/@.*/hue/L",
      .expected = {"2", "$1@$0", "hue@EXAMPLE.COM", "s/@.*/hue/L"},
    },
    {
      .input = "RULE:[1:$1@$0](hue@EXAMPLE.COM)    ",
      .expected = {"1","$1@$0", "hue@EXAMPLE.COM", ""},
    },
    {
      .input = "   DEFAULT   ",
      .expected = {"0", "DEFAULT", "",""},
    }

  };
  std::optional<std::array<std::string, HadoopAuthToLocal::kParseFields>>  parsed_rule;
  for(const auto &test : test_cases) {
    parsed_rule = HadoopAuthToLocal::parseAuthToLocalRule(test.input);
    ASSERT_TRUE(parsed_rule.has_value()) << "Failed to parse: " << test.input;
    EXPECT_EQ(parsed_rule->size(), HadoopAuthToLocal::kParseFields);
    EXPECT_EQ(parsed_rule->at(0), test.expected[0]);
    EXPECT_EQ(parsed_rule->at(1), test.expected[1]);
    EXPECT_EQ(parsed_rule->at(2), test.expected[2]);
    EXPECT_EQ(parsed_rule->at(3), test.expected[3]);
  }
  //R"(RULE:[2:$1@$0](.*@\QCOMPANY.PRI\E$)s/@\QCOMPANY.PRI\E$//)")
  //"mzeoli/somehost@COMPANY.PRI"
  //mzeoli
}


TEST(HadoopAuthToLocalTest, badParseAuthToLocalRuleTest) {
  std::vector<std::string> rules = {
    "RULE:[2:$1@$0](",
    "ABC:[3:$0@]",
    "RULE:[2:$1@$0](abc",
    "RULE:[](hue@EXAMPLE.COM)s/[ue]/b/g",
    "",
    "RULE: DEFAULT"};
  std::optional<std::array<std::string, HadoopAuthToLocal::kParseFields>> parsed_rule =
    HadoopAuthToLocal::parseAuthToLocalRule("RULE:[2:$1@$0](");

  for( const auto& rule : rules) {
    parsed_rule = HadoopAuthToLocal::parseAuthToLocalRule(rule);
    EXPECT_FALSE(parsed_rule.has_value());
  }
}

TEST(HadoopAuthToLocalTest, loadRulesTest) {
  HadoopAuthToLocal auth_to_local;
  std::vector<std::string> rules = {
    R"(<configuration><property><name>hadoop.security.auth_to_local</name><value>
RULE:[1:$1@$0](ambari-qa-rangerkerberos@EXAMPLE.COM)s/.*/ambari-qa/
RULE:[1:$1@$0](hbase-rangerkerberos@EXAMPLE.COM)s/.*/hbase/
RULE:[1:$1@$0](hdfs-rangerkerberos@EXAMPLE.COM)s/.*/hdfs/
RULE:[1:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/spark/
RULE:[1:$1@$0](yarn-ats-rangerkerberos@EXAMPLE.COM)s/.*/yarn-ats/
RULE:[1:$1@$0](.*@EXAMPLE.COM)s/@.*//
RULE:[2:$1@$0](dn@EXAMPLE.COM)s/.*/hdfs/
RULE:[2:$1@$0](hbase@EXAMPLE.COM)s/.*/hbase/
RULE:[2:$1@$0](hive@EXAMPLE.COM)s/.*/hive/
RULE:[2:$1@$0](jhs@EXAMPLE.COM)s/.*/mapred/
RULE:[2:$1@$0](kudu@EXAMPLE.COM)s/.*/kudu/
RULE:[2:$1@$0](livy@EXAMPLE.COM)s/.*/livy/
RULE:[2:$1@$0](nm@EXAMPLE.COM)s/.*/yarn/
RULE:[2:$1@$0](nn@EXAMPLE.COM)s/.*/hdfs/
RULE:[2:$1@$0](rangeradmin@EXAMPLE.COM)s/.*/ranger/
RULE:[2:$1@$0](rangerusersync@EXAMPLE.COM)s/.*/rangerusersync/
RULE:[2:$1@$0](rm@EXAMPLE.COM)s/.*/yarn/
RULE:[2:$1@$0](yarn@EXAMPLE.COM)s/.*/yarn/
RULE:[2:$1@$0](yarn-ats-hbase@EXAMPLE.COM)s/.*/yarn-ats/
DEFAULT
</value>
</property>
</configuration>)",

R"(<configuration>
<property>
<name>hadoop.security.auth_to_local</name>
<value>
RULE:[1:$1@$0](.*@\QBD.COMPANY.PRI\E$)s/@\QBD.COMPANY.PRI\E$//
RULE:[2:$1@$0](.*@\QBD.COMPANY.PRI\E$)s/@\QBD.COMPANY.PRI\E$//
RULE:[1:$1@$0](.*@\QCOMPANY.PRI\E$)s/@\QCOMPANY.PRI\E$//
RULE:[2:$1@$0](.*@\QCOMPANY.PRI\E$)s/@\QCOMPANY.PRI\E$//
DEFAULT
</value>
</property>
</configuration>)",
  };

  for (const auto& rule : rules){
    std::istringstream rule_stream(rule);
    EXPECT_EQ(auth_to_local.setRules(rule_stream), 0);
    EXPECT_TRUE(auth_to_local.rules_.size() > 0); 
      
  }
}

TEST(HadoopAuthToLocalTest, badLoadRulesTest) {
  HadoopAuthToLocal auth_to_local;
  std::vector<std::string> rules = {
    "",
    "<configuration></configuration>",
    "<configuration><property></property></configuration>",
    "<configuration><property><name>hadoop.security.auth_to_local</name></property></configuration>",
    "<configuration><property><name>hadoop.security.auth_to_local</name><value></value></property></configuration>"
  };
   for (const auto& rule : rules){
    std::istringstream rule_stream(rule);
    EXPECT_EQ(auth_to_local.setRules(rule_stream), -1);
    EXPECT_FALSE(auth_to_local.rules_.size() > 0); 
  }
}

                                 
} // namespace security
} // namespace kudu
