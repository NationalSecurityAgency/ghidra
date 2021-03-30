/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file test.hh
/// \brief Simple test framework
///
/// Include this file and any additional headers. Use TEST(testname) as
/// prototype in test function definitions.  E.g.
///     test.cc:
///         #include "float.hh"
///         #include "test.hh"
///
///         TEST(zero_is_less_than_one) {
///             ASSERT(0.0 < 1.0);
///         }
///

#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <set>

namespace {
    struct Test;
    typedef void (*testfunc_t)();

    std::vector<Test *> tests;

    struct Test {
        std::string name;
        testfunc_t func;

        Test(const std::string &name, testfunc_t func) : name(name), func(func) {
            tests.push_back(this);
        }
    };
} // namespace

#define TEST(testname)                                                                                                 \
    void testname();                                                                                                   \
    Test testname##_obj{ #testname, testname };                                                                        \
    void testname()

#define ASSERT(test)                                                                                                   \
    if (!(test)) {                                                                                                     \
        std::cerr << "  failed at " << __FILE__ << ":" << __LINE__ << " asserting \"" << #test << "\"." << std::endl;  \
        throw 0;                                                                                                       \
    }

#define ASSERT_EQUALS(a, b)                                                                                            \
    if ((a) != (b)) {                                                                                                  \
        std::stringstream ssa, ssb;                                                                                    \
        ssa << (a);                                                                                                    \
        ssb << (b);                                                                                                    \
        std::cerr << "  failed at " << __FILE__ << ":" << __LINE__ << " asserting \"" << ssa.str()                     \
                  << " == " << ssb.str() << "\"." << std::endl;                                                          \
        throw 0;                                                                                                       \
    }

#define ASSERT_NOT_EQUALS(a, b)                                                                                        \
    if ((a) == (b)) {                                                                                                  \
        std::stringstream ssa, ssb;                                                                                    \
        ssa << (a);                                                                                                    \
        ssb << (b);                                                                                                    \
        std::cerr << "  failed at " << __FILE__ << ":" << __LINE__ << " asserting \"" << ssa.str()                     \
                  << " != " << ssb.str() << "\"." << std::endl;                                                          \
        throw 0;                                                                                                       \
    }

int main(int argc, char **argv) {
    int total = 0;
    int passed = 0;

    std::set<std::string> testnames(argv + 1, argv + argc);

    for (auto &t : tests) {
        if(testnames.size()>0 && testnames.find(t->name)==testnames.end()) {
            continue;
        }
        std::cerr << "testing : " << t->name << " ..." << std::endl;
        ++total;
        try {
            t->func();
            ++passed;
            std::cerr << "  passed." << std::endl;
        } catch (...) {
        }
    }
    std::cerr << "==============================" << std::endl;
    std::cerr << passed << "/" << total << " tests passed." << std::endl;
}
