# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

set(GUTIL_SRCS
  bits.cc
  cpu.cc
  dynamic_annotations.c
  hash/city.cc
  hash/hash.cc
  hash/jenkins.cc
  int128.cc
  mathlimits.cc
  once.cc
  ref_counted.cc
  ref_counted_memory.cc
  spinlock.cc
  spinlock_internal.cc
  stringprintf.cc
  strings/ascii_ctype.cc
  strings/charset.cc
  strings/escaping.cc
  strings/human_readable.cc
  strings/join.cc
  strings/memutil.cc
  strings/numbers.cc
  strings/serialize.cc
  strings/split.cc
  strings/strcat.cc
  strings/stringpiece.cc
  strings/strip.cc
  strings/substitute.cc
  strings/util.cc
  strtoint.cc
  sysinfo.cc
  threading/thread_collision_warner.cc
  utf/rune.c
  walltime.cc)

if (NOT "${ARCH_NAME}" MATCHES "aarch64" AND NOT  "${ARCH_NAME}" MATCHES "ppc64le")
set(GUTIL_SRCS
  atomicops-internals-x86.cc
  ${GUTIL_SRCS})
endif()

set(GUTIL_LIBS
  glog
  protobuf)

if (NOT APPLE)
  set(GUTIL_LIBS
    ${GUTIL_LIBS}
    rt) # clock_gettime() requires -lrt
endif()

ADD_EXPORTABLE_LIBRARY(gutil
  SRCS ${GUTIL_SRCS}
  DEPS ${GUTIL_LIBS}
  # Disable warnings which trigger a lot in the Google code:
  COMPILE_FLAGS "-funsigned-char -Wno-char-subscripts")

#######################################
# Unit tests
#######################################

ADD_KUDU_TEST(strings/string_util-test)
ADD_KUDU_TEST(strings/numbers-test)
if (NOT APPLE)
  # The sysinfo-test consists of scenarios for Linux-specific function
  # ParseMaxCpuIndex(): that doesn't exist on macOS.
  ADD_KUDU_TEST(sysinfo-test)
endif()
