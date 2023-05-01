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
#include "test.hh"
#include "libdecomp.hh"

namespace ghidra {

vector<UnitTest *> UnitTest::tests;

/// Run all the tests unless a non-empty set of names is passed in.
/// In which case, only the named tests in the set are run.
/// \param testNames is the set of names
/// \return number of failed tests
int UnitTest::run(set<string> &testNames)

{
  int total = 0;
  int passed = 0;

  for(auto &t : UnitTest::tests) {
    if (testNames.size() > 0 && testNames.find(t->name) == testNames.end()) {
      continue;
    }
    cerr << "testing : " << t->name << " ..." << endl;
    ++total;
    try {
      t->func();
      ++passed;
      cerr << "  passed." << endl;
    } catch(...) {
    }
  }
  cerr << "==============================" << endl;
  cerr << passed << "/" << total << " tests passed." << endl;
  return total - passed;
}

/// Create list of the absolute path of all tests to be run
/// \param dirname is a directory containing the XML test files
/// \param testNames (if not empty) specifies particular tests to run
/// \param testFiles will hold the resulting list of paths
void gatherDataTests(const string &dirname,set<string> &testNames,vector<string> &testFiles)

{
  FileManage fileManage;

  set<string> fullNames;
  for(set<string>::iterator iter=testNames.begin();iter!=testNames.end();++iter) {
    string val = dirname;
    if (dirname.back() != '/')
      val += '/';
    val += *iter;
    fullNames.insert(val);
  }
  fileManage.addDir2Path(dirname);
  if (fullNames.empty()) {
    fileManage.matchList(testFiles,".xml",true);	// Take all test files
    return;
  }
  vector<string> allTestFiles;
  fileManage.matchList(allTestFiles,".xml",true);
  for(int4 i=0;i<allTestFiles.size();++i) {
    if (fullNames.find(allTestFiles[i]) != fullNames.end()) {	// Take tests matching into list of basenames
      testFiles.push_back(allTestFiles[i]);
    }
  }
}

/// \brief This function performs a saturating add on two numbers where the
/// result is to be used as an exit code for a CLI application.
///
/// \param current The current return code
/// \param add A number to add to the current return code
/// \return A number that can be used as an exit code up to 255.
int add_exit_code(int current, int add) {
  const int CLAMP = 255;
  int ret = current + add;
  if (current < 0 ||  	// Sanity checks
      current > CLAMP ||
      ret < current ||	// Can only happen due to overflow
      ret > CLAMP) {  	// Check clamp value
    ret = CLAMP;	// Set to max exit code
  }
  return ret;
}

} // End namespace ghidra

int main(int argc, char **argv) {
  using namespace ghidra;

  bool runUnitTests = true;
  bool runDataTests = true;

  argc -= 1;
  argv += 1;
  set<string> unitTestNames;
  set<string> dataTestNames;
  string dirname("../datatests");
  string sleighdirname("../../../../../../..");
  while (argc > 0) {
    string command(argv[0]);
    if (command == "-path") {
      dirname = argv[1];
      runDataTests = true;
      argv += 2;
      argc -= 2;
    }
    else if (command == "-sleighpath") {
      sleighdirname = argv[1];
      argv += 2;
      argc -= 2;
    }
    else if (command == "-usesleighenv") {
      const char *sleighhomepath = getenv("SLEIGHHOME");
      if (sleighhomepath != (const char *)0) {
        cout << "Using SLEIGHHOME=" << sleighhomepath << endl;
        sleighdirname = sleighhomepath;
      }
      else
        cout << "No SLEIGHHOME environment variable" << endl;
      argv += 1;
      argc -= 1;
    }
    else if (command == "unittests") {
      runUnitTests = true;
      runDataTests = false;	// Run only unit tests
      unitTestNames.insert(argv + 1,argv + argc);
      break;
    }
    else if (command == "datatests") {
      runUnitTests = false;	// Run only data-tests
      runDataTests = true;
      dataTestNames.insert(argv + 1,argv + argc);
      break;
    }
    else {
      cout << "USAGE: ghidra_test [-usesleighenv] [-sleighpath <sleighdir>] [-path <datatestdir>] [[unittests|datatests] [testname1 testname2 ...]]" << endl;
      return -1;
    }
  }
  startDecompilerLibrary(sleighdirname.c_str());

  // Keep track of failed tests as return code to indicate failures, clamped at
  // max exit code value in add_exit_code
  int failedTests = 0;
  if (runUnitTests) {
    int errors = UnitTest::run(unitTestNames);
    failedTests = add_exit_code(failedTests, errors);
  }
  if (runDataTests) {
    vector<string> testFiles;
    gatherDataTests(dirname,dataTestNames,testFiles);
    cout << endl << endl;
    int errors = FunctionTestCollection::runTestFiles(testFiles,cout);
    failedTests = add_exit_code(failedTests, errors);
  }

  return failedTests;
}
