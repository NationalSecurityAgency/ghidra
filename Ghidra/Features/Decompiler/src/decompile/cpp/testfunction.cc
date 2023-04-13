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
#include "ifacedecomp.hh"

namespace ghidra {

void FunctionTestProperty::startTest(void) const

{
  count = 0;
}

void FunctionTestProperty::processLine(const string &line) const

{
  if (std::regex_search(line,pattern))
    count += 1;
}

bool FunctionTestProperty::endTest(void) const

{
  return (count >= minimumMatch && count <= maximumMatch);
}

void FunctionTestProperty::restoreXml(const Element *el)

{
  name = el->getAttributeValue("name");
  istringstream s1(el->getAttributeValue("min"));
  s1 >> minimumMatch;
  istringstream s2(el->getAttributeValue("max"));
  s2 >> maximumMatch;
  pattern = std::regex(el->getContent());
}

void ConsoleCommands::readLine(string &line)

{
  if (pos >= commands.size()) {
    line.clear();
    return;
  }
  line = commands[pos];
  pos += 1;
}

/// \param s is the stream where command output is printed
/// \param comms is the list of commands to be issued
ConsoleCommands::ConsoleCommands(ostream &s,vector<string> &comms) :
    IfaceStatus("> ", s), commands(comms)
{
  pos = 0;
  IfaceCapability::registerAllCommands(this);
}

void ConsoleCommands::reset(void)

{
  pos = 0;
  inerror = false;
  done = false;
}

void FunctionTestCollection::clear(void)

{
  dcp->clearArchitecture();
  commands.clear();
  testList.clear();
  console->reset();
}

/// \param el is the root \<script> tag
void FunctionTestCollection::restoreXmlCommands(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    commands.push_back(subel->getContent());
  }
}

/// Instantiate an Architecture object
void FunctionTestCollection::buildProgram(DocumentStorage &docStorage)

{
  ArchitectureCapability *capa = ArchitectureCapability::getCapability("xml");
  if (capa == (ArchitectureCapability *)0)
    throw IfaceExecutionError("Missing XML architecture capability");
  dcp->conf = capa->buildArchitecture("test", "", console->optr);
  string errmsg;
  bool iserror = false;
  try {
    dcp->conf->init(docStorage);
    dcp->conf->readLoaderSymbols("::"); // Read in loader symbols
  } catch(DecoderError &err) {
    errmsg = err.explain;
    iserror = true;
  } catch(LowlevelError &err) {
    errmsg = err.explain;
    iserror = true;
  }
  if (iserror)
    throw IfaceExecutionError("Error during architecture initialization: " + errmsg);
}

/// Let each test initialize itself thru its startTest() method
void FunctionTestCollection::startTests(void) const

{
  list<FunctionTestProperty>::const_iterator iter;
  for(iter=testList.begin();iter!=testList.end();++iter) {
    (*iter).startTest();
  }
}

/// Each test gets a chance to process a line of output
/// \param line is the given line of output
void FunctionTestCollection::passLineToTests(const string &line) const

{
  list<FunctionTestProperty>::const_iterator iter;
  for(iter=testList.begin();iter!=testList.end();++iter) {
    (*iter).processLine(line);
  }
}

/// \brief Do the final evaluation of each test
///
/// This is called after each test has been fed all lines of output.
/// The result of each test is printed to the \e midStream, and then
/// failures are written to the lateStream in order to see a summary.
/// \param lateStream collects failures to display as a summary
void FunctionTestCollection::evaluateTests(list<string> &lateStream) const

{
  list<FunctionTestProperty>::const_iterator iter;
  for(iter=testList.begin();iter!=testList.end();++iter) {
    numTestsApplied += 1;
    if ((*iter).endTest()) {
      *console->optr << "Success -- " << (*iter).getName() << endl;
      numTestsSucceeded += 1;
    }
    else {
      *console->optr << "FAIL -- " << (*iter).getName() << endl;
      lateStream.push_back((*iter).getName());
    }
  }
}

/// \param s is the stream where output is sent during tests
FunctionTestCollection::FunctionTestCollection(ostream &s)

{
  console = new ConsoleCommands(s,commands);
  consoleOwner = true;
  dcp = (IfaceDecompData *)console->getData("decompile");
  console->setErrorIsDone(true);
  numTestsApplied = 0;
  numTestsSucceeded = 0;
}

FunctionTestCollection::FunctionTestCollection(IfaceStatus *con)

{
  console = con;
  consoleOwner = false;
  dcp = (IfaceDecompData *)console->getData("decompile");
  numTestsApplied = 0;
  numTestsSucceeded = 0;
}

FunctionTestCollection::~FunctionTestCollection(void)

{
  if (consoleOwner)
    delete console;
}

/// Load the architecture based on the discovered \<binaryimage> tag.
/// Collect the script commands and the specific tests.
/// \param filename is the XML file holding the test data
void FunctionTestCollection::loadTest(const string &filename)

{
  fileName = filename;
  DocumentStorage docStorage;
  Document *doc = docStorage.openDocument(filename);
  Element *el = doc->getRoot();
  if (el->getName() == "decompilertest")
    restoreXml(docStorage,el);
  else if (el->getName() == "binaryimage")
    restoreXmlOldForm(docStorage,el);
  else
    throw IfaceParseError("Test file " + filename + " has unrecognized XML tag: "+el->getName());
}

void FunctionTestCollection::restoreXml(DocumentStorage &store,const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter = list.begin();
  bool sawScript = false;
  bool sawTests = false;
  bool sawProgram = false;
  while(iter != list.end()) {
    const Element *subel = *iter;
    ++iter;
    if (subel->getName() == "script") {
      sawScript = true;
      restoreXmlCommands(subel);
    }
    else if (subel->getName() == "stringmatch") {
      sawTests = true;
      testList.emplace_back();
      testList.back().restoreXml(subel);
    }
    else if (subel->getName() == "binaryimage") {
      sawProgram = true;
      store.registerTag(subel);
      buildProgram(store);
    }
    else
      throw IfaceParseError("Unknown tag in <decompiletest>: "+subel->getName());
  }
  if (!sawScript)
    throw IfaceParseError("Did not see <script> tag in <decompiletest>");
  if (!sawTests)
    throw IfaceParseError("Did not see any <stringmatch> tags in <decompiletest>");
  if (!sawProgram)
    throw IfaceParseError("No <binaryimage> tag in <decompiletest>");
}

/// Pull the script and tests from a comment in \<binaryimage>
void FunctionTestCollection::restoreXmlOldForm(DocumentStorage &store,const Element *el)

{
  throw IfaceParseError("Old format test not supported");
}

/// Run the script commands on the current program.
/// Collect any bulk output, and run tests over the output.
/// Report test failures back to the caller
/// \param lateStream collects messages for a final summary
void FunctionTestCollection::runTests(list<string> &lateStream)

{
  ostream *origStream = console->optr;
  numTestsApplied = 0;
  numTestsSucceeded = 0;
  ostringstream midBuffer;		// Collect command console output
  console->optr = &midBuffer;
  ostringstream bulkout;
  console->fileoptr = &bulkout;
  mainloop(console);
  console->optr = origStream;
  console->fileoptr = origStream;
  if (console->isInError()) {
    *console->optr << "Error: Did not apply tests in " << fileName << endl;
    *console->optr << midBuffer.str() << endl;
    ostringstream fs;
    fs << "Execution failed for " << fileName;
    lateStream.push_back(fs.str());
    return;
  }
  string result = bulkout.str();
  if (result.size() == 0) {
    ostringstream fs;
    fs << "No output for " << fileName;
    lateStream.push_back(fs.str());
    return;
  }
  startTests();
  string::size_type prevpos = 0;
  string::size_type pos = result.find_first_of('\n');
  while(pos != string::npos) {
    string line = result.substr(prevpos,pos - prevpos);
    passLineToTests(line);
    prevpos = pos + 1;
    pos = result.find_first_of('\n',prevpos);
  }
  if (prevpos != result.size()) {
    string line = result.substr(prevpos);	// Process final line without a newline char
    passLineToTests(line);
  }
  evaluateTests(lateStream);
}

/// Run through all XML files in the given list, processing each in turn.
/// \param testFiles is the given list of test files
/// \param s is the output stream to print results to
int FunctionTestCollection::runTestFiles(const vector<string> &testFiles,ostream &s)

{
  int4 totalTestsApplied = 0;
  int4 totalTestsSucceeded = 0;
  list<string> failures;
  FunctionTestCollection testCollection(s);
  for(int4 i=0;i<testFiles.size();++i) {
    try {
      testCollection.clear();
      testCollection.loadTest(testFiles[i]);
      testCollection.runTests(failures);
      totalTestsApplied += testCollection.getTestsApplied();
      totalTestsSucceeded += testCollection.getTestsSucceeded();
    } catch(IfaceParseError &err) {
      ostringstream fs;
      fs << "Error parsing " << testFiles[i] << ": " << err.explain;
      s << fs.str() << endl;
      failures.push_back(fs.str());
    } catch(IfaceExecutionError &err) {
      ostringstream fs;
      fs << "Error executing " << testFiles[i] << ": " << err.explain;
      s << fs.str() << endl;
      failures.push_back(fs.str());
    }
  }

  s << endl;
  s << "Total tests applied = " << totalTestsApplied << endl;
  s << "Total passing tests = " << totalTestsSucceeded << endl;
  s << endl;
  if (!failures.empty()) {
    s << "Failures: " << endl;
    list<string>::const_iterator iter = failures.begin();
    for(int4 i=0;i<10;++i) {
      s << "  " << *iter << endl;
      ++iter;
      if (iter == failures.end()) break;
    }
  }
  return totalTestsApplied - totalTestsSucceeded;
}

} // End namespace ghidra
