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
/// \file testfunction.hh
/// \brief Framework for decompiler data driven single function tests
#ifndef __TESTFUNCTION_HH__
#define __TESTFUNCTION_HH__

#include "ifaceterm.hh"
#include "error.hh"
#include "xml.hh"
#include <regex>

namespace ghidra {

class IfaceDecompData;

/// \brief A single property to be searched for in the output of a function decompilation
///
/// This is generally a regular expression run over the characters in the
/// decompiled "source" form of the function.
/// The property may "match" more than once or not at all.
class FunctionTestProperty {
  int4 minimumMatch;		///< Minimum number of times property is expected to match
  int4 maximumMatch;		///< Maximum number of times property is expected to match
  string name;			///< Name of the test, to be printed in test summaries
  vector<std::regex> pattern;	///< Regular expression(s) to match against a line(s) of output
  mutable uint4 patnum;	///< Index of current pattern to match against
  mutable uint4 count;		///< Number of times regular expression has been seen
public:
  string getName(void) const { return name; }	///< Get the name of the property
  void startTest(void) const;		///< Reset "state", counting number of matching lines
  void processLine(const string &line) const;	///< Search thru \e line, update state if match found
  bool endTest(void) const;		///< Return results of property search
  void restoreXml(const Element *el);	///< Reconstruct the property from an XML tag
};

/// \brief A console command run as part of a test sequence
class ConsoleCommands : public IfaceStatus {
  vector<string> &commands;		///< Sequence of commands
  uint4 pos;				///< Position of next command to execute
  virtual void readLine(string &line);
public:
  ConsoleCommands(ostream &s,vector<string> &comms);		///< Constructor
  virtual void reset(void);		///< Reset console for a new program
  virtual bool isStreamFinished(void) const { return pos == commands.size(); }
};

/// \brief A collection of tests around a single program/function
///
/// The collection of tests is loaded from a single XML file via loadTest(),
/// and the tests are run by calling runTests().
/// An entire program is loaded and possibly annotated by a series of
/// console command lines.  Decompiler output is also triggered by a command,
/// and then the output is scanned for by the test objects (FunctionTestProperty).
/// Results of passed/failed tests are collected.  If the command line script
/// does not complete properly, this is considered a special kind of failure.
class FunctionTestCollection {
  IfaceDecompData *dcp;		///< Program data for the test collection
  string fileName;		///< Name of the file containing test data
  list<FunctionTestProperty> testList;	///< List of tests for this collection
  vector<string> commands;	///< Sequence of commands for current test
  IfaceStatus *console;		///< Decompiler console for executing scripts
  bool consoleOwner;		///< Set to \b true if \b this object owns the console
  mutable int4 numTestsApplied;		///< Count of tests that were executed
  mutable int4 numTestsSucceeded;	///< Count of tests that passed
  void clear(void);		///< Clear any previous architecture and function
  static string stripNewlines(const string &ref);	///< Convert any \e newline character to a \e space
  void restoreXmlCommands(const Element *el);	///< Reconstruct commands from an XML tag
  void buildProgram(DocumentStorage &store);	///< Build program (Architecture) from \<binaryimage> tag
  void startTests(void) const;	///< Initialize each FunctionTestProperty
  void passLineToTests(const string &line) const;	///< Let all tests analyze a line of the results
  void evaluateTests(list<string> &lateStream) const;
public:
  FunctionTestCollection(ostream &s);		///< Constructor
  FunctionTestCollection(IfaceStatus *con);	///< Constructor with preexisting console
  ~FunctionTestCollection(void);		///< Destructor
  int4 getTestsApplied(void) const { return numTestsApplied; }	///< Get the number of tests executed
  int4 getTestsSucceeded(void) const { return numTestsSucceeded; }	///< Get the number of tests that passed
  int4 numCommands(void) const { return commands.size(); }	///< Get the number of commands in the current script
  string getCommand(int4 i) const { return commands[i]; }	///< Get the i-th command
  void loadTest(const string &filename);	///< Load a test program, tests, and script
  void restoreXml(DocumentStorage &store,const Element *el);	///< Load tests from a \<decompilertest> tag.
  void restoreXmlOldForm(DocumentStorage &store,const Element *el);	///< Load tests from \<binaryimage> tag.
  void runTests(list<string> &lateStream);	///< Run the script and perform the tests
  static int runTestFiles(const vector<string> &testFiles,ostream &s);	///< Run tests for each listed file
};

} // End namespace ghidra
#endif
