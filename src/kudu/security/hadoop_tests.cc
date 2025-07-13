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
#include <glog/logging.h>
#include <string>
#include <thread>
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
      .input = "s/@.+//g/L",
      .expected = {"@.+", "", "gL"},
    },
    {
      .input = "s/@.//L",
      .expected = {"@.", "", "L"},
    },
    {
      .input = "s/@.//L",
      .expected = {"@.", "", "L"},
    },
    {
      .input = "s/.*/yarn-ats/g",
      .expected = {".*", "yarn-ats", "g"},
    },
    {
      .input = R"(s/\\/b/)",
      .expected = {"\\\\", "b", ""},
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
  std::vector<std::string> input = {"r/@.//L/g",R"(s/\//)", "s|@.//L", "s/@.//L/gL", "  ", "s|abc|def|"};
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
      .expected = {"2", "$1-$2@$0", ".*@COMPANY\\.PRI$", "s/@\\QCOMPANY.PRI\\E$//"},
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
    },
    {
      .input = "RULE:[2:$1@$0](abc\\)def)s/.*//",
      .expected = {"2", "$1@$0", "abc\\)def", "s/.*//"},
    },
    {
      .input = "RULE:[2:$1@\\]0](hue@EXAMPLE.COM)s/.*/hue/",
      .expected = {"2", "$1@]0", "hue@EXAMPLE.COM", "s/.*/hue/"}
    },
    {
      .input = R"(RULE:[1:$1](App\..*)s/App\.(.*)/$1/g)",
      .expected = {"1", "$1", "App\\..*", "s/App\\.(.*)/$1/g"},
    },
    {
      .input = R"(RULE:[2:$1@$0]())",
      .expected = {"2", "$1@$0", "", ""},
    },
    {
      .input = R"(RULE:[2:$1@$0])",
      .expected = {"2", "$1@$0", "", ""},
    },
  };
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  std::optional<std::array<std::string, HadoopAuthToLocal::kParseFields>>  parsed_rule;
  for(const auto &test : test_cases) {
    parsed_rule = auth.parseAuthToLocalRule(test.input);
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
    "  ",
    "RULE: DEFAULT",
    "RULE:[2:$1@$0]()/",
    "rule:[2:$1@$0(abc)",
    "RULE:[](hue@EXAMPLE.COM)/s/[ue]/b/g",

  };
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  std::optional<std::array<std::string, HadoopAuthToLocal::kParseFields>> parsed_rule =
    auth.parseAuthToLocalRule("RULE:[2:$1@$0](");

  for( const auto& rule : rules) {
    parsed_rule = auth.parseAuthToLocalRule(rule);
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
    EXPECT_EQ(auth_to_local.setRules(rule_stream), true);
    EXPECT_TRUE(auth_to_local.rulesByFields_.size() > 0); 
  }
}

TEST(HadoopAuthToLocalTest, badLoadRulesTest) {
  int old_minloglevel = FLAGS_minloglevel;
  FLAGS_minloglevel = google::GLOG_FATAL;
  std::string long_string = "<configuration><property><name>hadoop.security.auth_to_local</name>" 
    "<value></value></property></configuration>";



  HadoopAuthToLocal auth_to_local;
  std::vector<std::string> rules = {
  "",
  "<configuration></configuration>",
  "<configuration><property></property></configuration>",
  "<configuration><property><name>hadoop.security.auth_to_local</name></property></configuration>",
  long_string,
  "<configuration><property><value></property></configuration>",
    
  };
   for (const auto& rule : rules){
    std::istringstream rule_stream(rule);
    EXPECT_EQ(auth_to_local.setRules(rule_stream), false);
    EXPECT_FALSE(auth_to_local.rulesByFields_.size() > 0); 
  }
  FLAGS_minloglevel = old_minloglevel;
}

TEST(HadoopAuthToLocalTest, checkPrincipalTest) {
  std::vector<std::string> valid_principals = {
    "hue/my_host@EXAMPLE.COM",
    "spark-user@EXAMPLE.COM",
    "livy/another_host@MY.OTHER.HOST",
  };
  std::vector<std::string> invalid_principals = {
    "",
    "my_principal",
    "user/host@",
    "@HOST.COM",
    "user@",
    "user@host@ANOTHER_HOST",
    "us er@HOST.COM",
  };
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  for(const auto& principal : valid_principals) {
    EXPECT_TRUE(auth.checkPrincipal(principal)) 
      << "Failed to validate principal: " << principal;
  }

  for(const auto& principal : invalid_principals) {
    EXPECT_FALSE(auth.checkPrincipal(principal)) 
      << "Failed to invalidate principal: " << principal;
  }
}

TEST(HadoopAuthToLocalTest, formatTest){
  struct TestCase {
    std::string input;
    std::vector<std::string> values;
    std::string expected;
  };

  std::vector<TestCase> test_cases = {
    {
      .input = "$1@$0",
    .values = {"host", "user"},
      .expected = "user@host",
    },
    {
      .input = "$1-$2@$0",
      .values = {"host", "part1", "part2", },
      .expected = "part1-part2@host",
    },
    {
      .input = "$1$2/$0abc",
      .values = {"host", "123", "456"},
      .expected = "123456/hostabc",
    },
    {
      .input = "$1-$2@$0",
      .values = {"host", "", "", "my_name"},
      .expected = "-@host",
    },
    {
      .input = "$1@$0",
      .values = {"EXAMPLE.COM", "hbase"},
      .expected = "hbase@EXAMPLE.COM",
    }
  };
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  for(const auto& test : test_cases) {
    std::optional<std::string> result = auth.format(test.input, test.values);
    ASSERT_TRUE(result.has_value()) << "Failed to format: " << test.input;
    EXPECT_EQ(result.value(), test.expected) << "Expected: " << test.expected 
      << " but got: " << result.value() << " for input: " << test.input;
  }
}
TEST(HadoopAuthToLocalTest, badFormatTest){
  int old_minloglevel = FLAGS_minloglevel;
  FLAGS_minloglevel = google::GLOG_FATAL;
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  std::optional<std::string> failure = auth.format("$1-$2$9@$0", {"host", "part1"});
  EXPECT_FALSE(failure.has_value()) << "Expected failure for invalid format string";
  std::string fmt = "$x@$$9";
  EXPECT_FALSE(auth.format(fmt, {"EXAMPLE.COM", "user"}).has_value()) 
    << "Expected failure for invalid format string: " << fmt;
  FLAGS_minloglevel = old_minloglevel;
}

TEST(HadoopAuthToLocalTest, getRealmTest) {
  struct TestCase {
    std::string input;
    std::string expected;
  };
  std::vector<TestCase> test_cases = {
    {
      .input = "abc@EXAMPLE.COM",
      .expected = "EXAMPLE.COM",
    },
    {
      .input = "user/hostname@REALM.NET",
      .expected = "REALM.NET",
    },
    {
      .input = "invalid_principal",
      .expected = "",
    },
  };
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  for (const auto& test : test_cases) {
    std::optional<std::string> realm = auth.getRealm(test.input);
    ASSERT_TRUE(realm.has_value()) << "Failed to get realm from: " << test.input;
    EXPECT_EQ(realm.value(), test.expected) << "Expected: " << test.expected 
      << " but got: " << realm.value() << " for input: " << test.input;
  }
}

TEST(HadoopAuthToLocalTest, numberOfFieldsTest) {
  struct TestCase {
    std::string input;
    int expected;
  };
  std::vector<TestCase> test_cases = {
    {
      .input = "hue-yarnkerberos@EXAMPLE.COM",
    .expected = 1, 
    },
    {
      .input = "spark/my_host@EXAMPLE.NET",
      .expected = 2,
    },
    {.input = "not_valid",
    .expected = -1, 
    },
  };
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  for (const auto& test : test_cases){
    int num_fields = auth.numberOfFields(test.input);
    ASSERT_EQ(num_fields, test.expected) 
      << "Expected: " << test.expected << " but got: " 
      << num_fields << " for input: " << test.input;
  }
}

TEST(HadoopAuthToLocalTest, initRuleTest) {
  struct TestCase {
    std::string input;
    std::string expected_fmt;
    std::string expected_regexMatchString;
    bool has_sed_rule;
  };
  std::vector<TestCase> test_cases = {
    {
      .input = "RULE:[2:$1@$0](hive@EXAMPLE.COM)s/.*/hive/",
      .expected_fmt = "$1@$0",
      .expected_regexMatchString = "hive@EXAMPLE.COM",
      .has_sed_rule = true,
    },
    {
      .input = "RULE:[1:$1@$0]([aeiou]+@.*EXAMPLE.COM)s/[ae]/c/g",
      .expected_fmt = "$1@$0",
      .expected_regexMatchString = "[aeiou]+@.*EXAMPLE.COM",
      .has_sed_rule = true,
    },
    {
      .input = " RULE:[2:$1@$0](hm@.*EXAMPLE.COM)",
      .expected_fmt = "$1@$0",
      .expected_regexMatchString = "hm@.*EXAMPLE.COM",
      .has_sed_rule = false,
    },
    {
      .input = "RULE:[1:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/spark/",
      .expected_fmt = "$1@$0",
      .expected_regexMatchString = "spark-rangerkerberos@EXAMPLE.COM",
      .has_sed_rule = true,
    },
    {
      .input = R"(RULE:[1:$1@$0](.*@\QBD.COMPANY.PRI\E$)s/@\QBD.COMPANY.PRI\E$//)",
      .expected_fmt = "$1@$0",
      .expected_regexMatchString = ".*@BD\\.COMPANY\\.PRI$",
      .has_sed_rule = true,
    },
    {
      .input = R"(RULE:[1:$1]s/@.*//g)",
      .expected_fmt = "$1",
      .expected_regexMatchString = "",
      .has_sed_rule = true,
    },
 {
      .input = R"(RULE:[1:$1]()s/@.*//g)",
      .expected_fmt = "$1",
      .expected_regexMatchString = "",
      .has_sed_rule = true,
    },
  };
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  for (const auto& test : test_cases) {
    std::optional<HadoopAuthToLocal::Rule> rule = auth.initRule(test.input);
    ASSERT_TRUE(rule.has_value()) << "Failed to initialize rule from: " << test.input;
    EXPECT_EQ(rule->fmt, test.expected_fmt) << "Expected format: " << test.expected_fmt 
      << " but got: " << rule->fmt << " for input: " << test.input;
    EXPECT_EQ(rule->regexMatchString, test.expected_regexMatchString) 
      << "Expected regex match string: " << test.expected_regexMatchString 
      << " but got: " << rule->regexMatchString << " for input: " << test.input;
    EXPECT_EQ(rule->sedRule.has_value(), test.has_sed_rule) 
      << "Expected hasSedRule: " << test.has_sed_rule 
      << " but got: " << rule->sedRule.has_value() << " for input: " << test.input;
  }
}
TEST(HadoopAuthToLocalTest, badInitRulesTest) {
  struct TestCase {
    std::string input;
    std::string expected_fmt;
    std::string expected_regexMatchString;
    bool has_sed_rule;
  };
  int old_minloglevel = FLAGS_minloglevel;
  FLAGS_minloglevel = google::GLOG_FATAL;

  std::vector<std::string> bad_rules = {
    "",
    "   ",
    "RULE:[2:$1@$0](",
    "RULE:[2:$1@$0](abc",
    "RULE:[2:$1@$0]abc)",
    "RULE:[2:$1@$0]()s/.*/hive/\\",
    "RULE:[2:](hive@EXAMPLE.COM)s/.*/hive/",
    "RULE:[2:$1@$0(hive@EXAMPLE.COM)s/.*/hive/",
    "RULE:[2:$1@$0](hive@EXAMPLE.COMs/.*/hive/",
    "RULE:[$1@$0](hive@EXAMPLE.COM)s/.*/hive/",
    "RULE:[2$1@$0](hive@EXAMPLE.COM)s/.*/hive/",
    "rule:[2:$1@$0](hive@EXAMPLE.COM)s/.*/hive/",
    "RULE:[2:$1@$0](hive@EXAMPLE.COM)s/.*/hive/EXTRA",
    "RULE:[2:$1@$0](hive@EXAMPLE.COM)garbage",
    "RULE:2:$1](hive@EXAMPLE.COM)s/.*/hive/",
    "RULE:2:$1(hive@EXAMPLE.COM)s/.*/hive/",
    "DEFAULT extra",
  };
  HadoopAuthToLocal auth = HadoopAuthToLocal();
  auth.setDefaultRealm("EXAMPLE.COM");
  for (const auto& bad_rule : bad_rules) {
    std::optional<HadoopAuthToLocal::Rule> rule = auth.initRule(bad_rule);
    ASSERT_FALSE(rule.has_value()) << "Expected failure for invalid rule: " << bad_rule;
  }
  FLAGS_minloglevel = old_minloglevel;
}

TEST(HadoopAuthToLocalTest, transformPrincipalTest){
  struct TestCase {
    std::string input;
    std::string principal;
    std::string expected;
  };
  std::vector<TestCase> test_cases = {
    {
      .input = "RULE:[2:$1@$0](hive@EXAMPLE.COM)s/.*/hive/",
      .principal = "hive/my_host@EXAMPLE.COM",
      .expected = "hive",
    },
    {
      .input = "RULE:[1:$1@$0]([aeiou]+@.*EXAMPLE.COM)s/[aeE]/c/g",
      .principal = "aaee@EXAMPLE.COM",
      .expected = "cccc@cXAMPLc.COM",
    },
    {
      .input = " RULE:[2:$1@$0](hm@.*EXAMPLE.COM)s/@.+//",
      .principal = "hm/my_other_host@SOMEEXAMPLE.COM",
      .expected = "hm",
    },
    {
      .input = "RULE:[2:$1@$0](hbase@EXAMPLE.COM)s/.*/hbase/",
      .principal = "hbase/hadoophost1@EXAMPLE.COM",
      .expected = "hbase",
    },
    {
      .input = "RULE:[1:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/spark/",
      .principal = "spark-rangerkerberos@EXAMPLE.COM",
      .expected = "spark",
    },
    {
      .input = "RULE:[1:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/SPARK/L",
      .principal = "spark-rangerkerberos@EXAMPLE.COM",
      .expected = "spark",
    },
    {
      .input = R"(RULE:[2:$1@$0](.*@\QBD.COMPANY.PRI\E$)s/@\QBD.COMPANY.PRI\E$//)",
      .principal = "mzeoli/somehost@BD.COMPANY.PRI",
      .expected = "mzeoli",
    },
    {
      .input = "DEFAULT",
      .principal = "spark/my_host@EXAMPLE.COM",
      .expected = "spark",
    },
    {
      .input = "DEFAULT",
      .principal = "spark-user@EXAMPLE.COM",
      .expected = "spark-user",
    },
    {
      .input = R"(RULE:[1:$1](App\..*)s/App\.(.*)/$1/g)",
      .principal = "App.kudu@EXAMPLE.COM",
      .expected = "kudu",
    },
    {
      .input = R"(RULE:[2:$1](App\..*)s/App\.(.*)/$1/g)",
      .principal = "App.kudu/myhost@EXAMPLE.COM",
      .expected = "kudu",
    },
  };
  HadoopAuthToLocal auth_to_local = HadoopAuthToLocal();
  auth_to_local.setDefaultRealm("EXAMPLE.COM");
  auth_to_local.ruleMechanism_ = HadoopAuthToLocal::RuleMechanism::MIT;
  for (const auto& test : test_cases) {
    std::optional<HadoopAuthToLocal::Rule> rule = auth_to_local.initRule(test.input);

    ASSERT_TRUE(rule.has_value()) << "Failed to initialize rule from: '" << test.input << "'";
    std::vector<std::string> fields = auth_to_local.extractFields(test.principal);
    std::string realm = auth_to_local.getRealm(test.principal);

    std::optional<std::string> formatted_principal = auth_to_local.transformPrincipal(
      *rule, test.principal, fields, realm);
    ASSERT_TRUE(formatted_principal.has_value()) 
      << "Failed to create formatted principal for: " << test.principal;
    EXPECT_EQ(formatted_principal.value(), test.expected) 
      << "Expected: " << test.expected << " but got: " << formatted_principal.value() 
      << " for input: " << test.input;
  }
}
TEST(HadoopAuthToLocalTest, negativeTransformPrincipalTest) {
  struct TestCase {
    std::string input;
    std::string principal;
    std::string expected;
  };

  std::vector<TestCase> negative_test_cases = {
    {
      .input = "RULE:[2:$1@$0](hive@EXAMPLE.COM)s/.*/hive/",
      .principal = "impala/my_host@EXAMPLE.COM",
    },
    {
      .input = "RULE:[1:$1@$0]([aeiou]+@.*EXAMPLE.COM)s/[aeE]/c/g",
      .principal = "bcee@EXAMPLE.COM",
    },
    {
      .input = "RULE:[2:$1@$0](hm@.*EXAMPLE.COM)s/@.+//",
      .principal = "xx/my_other_host@EXAMPLE.COM",
    },
    {
      .input = "RULE:[1:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/spark/",
      .principal = "spark@EXAMPLE.COM",
    },
    {
      .input = "RULE:[2:$1@$0](hm@.+EXAMPLE.COM)s/@.+//",
      .principal = "hm@EXAMPLE.COM",
    },
    {
      .input = R"(RULE:[2:$1@$0](.*@\QBD.COMPANY.PRI\E$)s/@\QBD.COMPANY.PRI\E$//)",
      .principal = "mzeoli/somehost@OTHERREALM.COM",
    },
    {
      .input = "RULE:[2:$1@$0](hm@.+EXAMPLE.COM)s/@.+//",
      .principal = "hm/my_other_host@EXAMPLE.ORG",
    },
    {
      .input = "RULE:[1:$1@$0](spark@EXAMPLE.COM)s/.*/spark/",
      .principal = "sparkly@EXAMPLE.COM",
    },
    {
      .input = "RULE:[1:$1@$0](spark@EXAMPLE.COM)s/.*/spark/",
      .principal = "spark@ExAmPle.COM",
    },
    {
      .input = "DEFAULT",
      .principal = "spark/otherhost@NOTEXAMPLE.ORG",
    },
    {
      .input = "DEFAULT",
      .principal = " ",
    }
  };
  HadoopAuthToLocal auth_to_local = HadoopAuthToLocal();
  auth_to_local.ruleMechanism_ = HadoopAuthToLocal::RuleMechanism::MIT;
  auth_to_local.setDefaultRealm("EXAMPLE.COM");

  for (const auto& test : negative_test_cases) {
    std::vector<std::string> fields = auth_to_local.extractFields(test.principal);
    std::string realm = auth_to_local.getRealm(test.principal);
    std::optional<HadoopAuthToLocal::Rule> rule = auth_to_local.initRule(test.input);
    ASSERT_TRUE(rule.has_value()) << "Failed to initialize rule from: " << test.input;
    std::optional<std::string> formatted_principal = auth_to_local.transformPrincipal(
      *rule, test.principal, fields, realm);
    ASSERT_FALSE(formatted_principal.has_value()) 
      << "Expected failure for principal: " << test.principal 
      << " with rule: " << test.input;
  }
}

TEST(HadoopAuthToLocalTest, matchPrincipalAgainstAllRulesTest) {
  struct TestCase {
    std::string principal;
    std::string expected;
  };
  HadoopAuthToLocal auth_to_local;
  auth_to_local.setDefaultRealm("EXAMPLE.COM");
  std::vector<std::string> rules = {
    R"(<configuration><property><name>hadoop.security.auth_to_local</name><value>
RULE:[1:$1@$0](onlyfirstmatches@EXAMPLE.COM)s/@.*//
RULE:[1:$1@$0](onlyfirstmatches@EXAMPLE.COM)s/.*/shouldnothappen/
RULE:[1:$1@$0](ambari-qa-rangerkerberos@EXAMPLE.COM)s/.*/ambari-qa/
RULE:[1:$1@$0](hbase-rangerkerberos@EXAMPLE.COM)s/.*/hbase/
RULE:[1:$1@$0](hdfs-rangerkerberos@EXAMPLE.COM)s/.*/hdfs/
RULE:[1:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/spark/
RULE:[1:$1@$0](spark-rangerkerberos@EXAMPLE.COM)s/.*/SECONDSPARK/
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
<property>
  <name>hadoop.security.auth_to_local.mechanism</name>
  <value>MIT</value>
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
RULE:[2:$1@$0](.*@\QCOMPANY$PRI\E$)s/@\QCOMPANY$PRI\E$//
DEFAULT
</value>
</property>
</configuration>)",
  };

  std::vector<TestCase> test_cases = {
    {
      .principal = "onlyfirstmatches@EXAMPLE.COM",
      .expected = "onlyfirstmatches",
    },
    {
      .principal = "ambari-qa-rangerkerberos@EXAMPLE.COM",
      .expected = "ambari-qa"
    },
    {
      .principal = "hbase/hadoophost1@EXAMPLE.COM",
      .expected = "hbase"
    },
    {
      .principal = "ll/somehost@EXAMPLE.COM",
      .expected = "ll"
    },
    {
      .principal = "nn/hadoophost2@EXAMPLE.COM",
      .expected = "hdfs"
    },
    {
      .principal = "user@EXAMPLE.COM",
      .expected = "user"
    },
    {
      .principal = "livy/sparkhost.abc.dev@EXAMPLE.COM",
      .expected = "livy"
    },
    {
      .principal = "myotherprincipal@EXAMPLE.COM",
      .expected = "myotherprincipal",
    },
  };

  std::istringstream rule_stream(rules[0]);
  ASSERT_TRUE(auth_to_local.setRules(rule_stream));
  ASSERT_TRUE(auth_to_local.rulesByFields_.size() > 0); 
  EXPECT_EQ(auth_to_local.ruleMechanism_, HadoopAuthToLocal::RuleMechanism::MIT);

  for (const auto& test : test_cases) {
    std::optional<std::string> result = auth_to_local.matchPrincipalAgainstRules(test.principal);
    ASSERT_TRUE(result.has_value()) << "Failed to match principal: " << test.principal;
    EXPECT_EQ(result.value(), test.expected) 
      << "Expected: " << test.expected << " but got: " << result.value() 
      << " for principal: " << test.principal;
  }
    
  test_cases = std::vector<TestCase>{
    {
        .principal = "alice@BD.COMPANY.PRI",
        .expected = "alice"
    },
    {
        .principal = "bob/server1@BD.COMPANY.PRI",
        .expected = "bob"
    },
    {
        .principal = "carol@COMPANY.PRI",
        .expected = "carol"
    },
    {
        .principal = "dave/host123@COMPANY.PRI",
        .expected = "dave"
    },
    {
      .principal = "eve/host@COMPANY$PRI",
      .expected = "eve",
    },
  };

  auth_to_local.setDefaultRealm("COMPANY.PRI");
  std::istringstream rule_stream_two(rules[1]);
  ASSERT_TRUE(auth_to_local.setRules(rule_stream_two));
  ASSERT_TRUE(auth_to_local.rulesByFields_.size() > 0); 


  for (const auto& test : test_cases) {
    std::optional<std::string> result = auth_to_local.matchPrincipalAgainstRules(test.principal);
    ASSERT_TRUE(result.has_value()) << "Failed to match principal: " << test.principal;
    EXPECT_EQ(result.value(), test.expected) 
      << "Expected: " << test.expected << " but got: " << result.value() 
      << " for principal: " << test.principal;
  }
}

TEST(HadoopAuthToLocalTest, threadSafeTest){
  
  int old_minloglevel = FLAGS_minloglevel;
  FLAGS_minloglevel = google::GLOG_FATAL;
  std::unique_ptr<HadoopAuthToLocal> auth_to_local(new HadoopAuthToLocal);
  auth_to_local->setDefaultRealm("EXAMPLE.COM");
  std::string rule_xml = R"(
  <configuration>
    <property>
      <name>hadoop.security.auth_to_local</name>
      <value>
RULE:[1:$1@$0](user@EXAMPLE.COM)s/.*/user/
DEFAULT
      </value>
    </property>
  </configuration>
  )";
  std::istringstream rule_stream(rule_xml);
  ASSERT_EQ(auth_to_local->setRules(rule_stream), true);

  std::atomic<bool> start{false};
  std::atomic<int> success_count{0};
  int num_readers = 4;
  int num_writers = 2;
  int iterations = 50;

  
  auto reader = [&]() {
    while (!start) {}
      for (int i = 0; i < iterations; ++i) {
        auto result = auth_to_local->matchPrincipalAgainstRules("user@EXAMPLE.COM");
          if (result.has_value() && result.value() == "user") {
            ++success_count;
          }
      }
  };

  auto writer = [&]() {
    while (!start) {}
      for (int i = 0; i < iterations; ++i) {
        std::istringstream rewrite(rule_xml);
        auth_to_local->setRules(rewrite);
        auth_to_local->setDefaultRealm("EXAMPLE.COM");
      }
  };

  std::vector<std::thread> threads;
  threads.reserve(num_readers + num_writers);
  for (int i = 0; i < num_readers; ++i)
    threads.emplace_back(reader);
  for (int i = 0; i < num_writers; ++i)
    threads.emplace_back(writer);

  start = true;
  for (auto& thr : threads) thr.join();

  EXPECT_EQ(success_count.load(), num_readers * iterations);
  FLAGS_minloglevel = old_minloglevel;
}

TEST(HadoopAuthToLocalTest, ruleMechanismTest) {
  struct TestCase {
    std::string input;
    bool valid;
  };

  HadoopAuthToLocal auth_to_local;
  auth_to_local.setDefaultRealm("EXAMPLE.COM");

  std::istringstream rule_stream(
    "<configuration><property><name>hadoop.security.auth_to_local"
    "</name><value>RULE:[1:$1]\nDEFAULT</value></property></configuration>");
  ASSERT_TRUE(auth_to_local.setRules(rule_stream));
  auth_to_local.ruleMechanism_ = HadoopAuthToLocal::RuleMechanism::HADOOP;
  std::vector<TestCase> hadoop_cases = {
    {
      .input = "hdfs",
      .valid = true,
    },
    {
      .input = "hdfs-someservice",
      .valid = true,
    },
    {
      .input = "hdfs/host",
      .valid = false,
    },
    {
      .input = "hdfs@hostname",
      .valid = false,
    },
  };

  std::vector<TestCase> mit_cases = {
    {
      .input = "hdfs",
      .valid = true,
    },
    {
      .input = "hdfs/host",
      .valid = true,
    },
    {
      .input = "hdfs@hostname",
      .valid = true,
    }
  };

  for (const auto& test : hadoop_cases) {
    EXPECT_EQ(auth_to_local.simplePatternCheck(test.input), test.valid) 
      << "Hadoop rule validation failed for: " << test.input;
  }

  auth_to_local.ruleMechanism_ = HadoopAuthToLocal::RuleMechanism::MIT;

  for (const auto& test : mit_cases) {
    EXPECT_EQ(auth_to_local.simplePatternCheck(test.input), test.valid) 
      << "MIT rule validation failed for: " << test.input;
  }
}

TEST(PrincipalLRUCacheTest, LRUOrder) {
  PrincipalLRUCache cache(2);
  cache.put("a", "A");
  cache.put("b", "B");

  cache.get("a");
  cache.put("c", "C");

  EXPECT_FALSE(cache.get("b").has_value());

  EXPECT_TRUE(cache.get("a").has_value());
  EXPECT_TRUE(cache.get("c").has_value());
}
TEST(PrincipalLRUCacheTest, HandlesOptionalNone) {
  PrincipalLRUCache cache(1);

  cache.put("x", std::nullopt);
  std::optional<std::optional<std::string>> value = cache.get("x");
  ASSERT_TRUE(value.has_value());
  EXPECT_FALSE(value.value().has_value()); 
}

} // namespace security
} // namespace kudu
