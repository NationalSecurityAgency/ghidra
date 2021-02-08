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
#include "testfunction.hh"
#include "filemanage.hh"

void FunctionTestProperty::startTest(void) const

{
  count = 0;
}

void FunctionTestProperty::processLine(const string &line) const

{
  if (regex_search(line,pattern))
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
  pattern = regex(el->getContent());
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

ConsoleCommands::ConsoleCommands(void) :
    IfaceStatus("> ", cout)
{
  pos = 0;
  IfaceCapability::registerAllCommands(this);
}

void ConsoleCommands::reset(void)

{
  commands.clear();
  pos = 0;
  inerror = false;
  done = false;
}

/// \param el is the root \<script> tag
void ConsoleCommands::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    commands.push_back(subel->getContent());
  }
  pos = 0;
}

void FunctionTestCollection::clear(void)

{
  dcp->clearArchitecture();
  testList.clear();
  console.reset();
}

/// Instantiate an Architecture object
void FunctionTestCollection::buildProgram(DocumentStorage &docStorage)

{
  ArchitectureCapability *capa = ArchitectureCapability::getCapability("xml");
  if (capa == (ArchitectureCapability *)0)
    throw IfaceExecutionError("Missing XML architecture capability");
  dcp->conf = capa->buildArchitecture("test", "", console.optr);
  string errmsg;
  bool iserror = false;
  try {
    dcp->conf->init(docStorage);
    dcp->conf->readLoaderSymbols("::"); // Read in loader symbols
  } catch(XmlError &err) {
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
/// \param midStream is the stream write results to as the test is performed
/// \param lateStream collects failures to display as a summary
void FunctionTestCollection::evaluateTests(ostream &midStream,list<string> &lateStream) const

{
  list<FunctionTestProperty>::const_iterator iter;
  for(iter=testList.begin();iter!=testList.end();++iter) {
    numTestsApplied += 1;
    if ((*iter).endTest()) {
      midStream << "Success -- " << (*iter).getName() << endl;
      numTestsSucceeded += 1;
    }
    else {
      midStream << "FAIL -- " << (*iter).getName() << endl;
      lateStream.push_back((*iter).getName());
    }
  }
}

FunctionTestCollection::FunctionTestCollection(void)

{
  dcp = (IfaceDecompData *)console.getData("decompile");
  console.setErrorIsDone(true);
  numTestsApplied = 0;
  numTestsSucceeded = 0;
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
  clear();
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
      console.restoreXml(subel);
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
  clear();
  throw IfaceParseError("Old format test not supported");
}

/// Run the script commands on the current program.
/// Collect any bulk output, and run tests over the output.
/// Report test failures back to the caller
/// \param midStream is the output stream to write to during the test
/// \param lateStream collects messages for a final summary
void FunctionTestCollection::runTests(ostream &midStream,list<string> &lateStream)

{
  numTestsApplied = 0;
  numTestsSucceeded = 0;
  ostringstream midBuffer;		// Collect command console output
  console.optr = &midBuffer;
  ostringstream bulkout;
  console.fileoptr = &bulkout;
  mainloop(&console);
  console.optr = &midStream;
  console.fileoptr = &midStream;
  if (console.isInError()) {
    midStream << "Error: Did not apply tests in " << fileName << endl;
    midStream << midBuffer.str() << endl;
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
  evaluateTests(midStream, lateStream);
}

/// Run through all XML files in the given directory, processing each in turn.
/// \param dirname is a directory containing the XML test files
/// \param testNames (if not empty) specifies particular tests to run
void FunctionTestCollection::runTestCollections(const string &dirname,set<string> &testNames)

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
  vector<string> testFiles;
  fileManage.matchList(testFiles,".xml",true);

  int4 totalTestsApplied = 0;
  int4 totalTestsSucceeded = 0;
  list<string> failures;
  FunctionTestCollection testCollection;
  for(int4 i=0;i<testFiles.size();++i) {
    if (!fullNames.empty() && fullNames.find(testFiles[i]) == fullNames.end())
      continue;
    try {
      testCollection.loadTest(testFiles[i]);
      testCollection.runTests(cout, failures);
      totalTestsApplied += testCollection.getTestsApplied();
      totalTestsSucceeded += testCollection.getTestsSucceeded();
    } catch(IfaceParseError &err) {
      ostringstream fs;
      fs << "Error parsing " << testFiles[i] << ": " << err.explain;
      cout << fs.str() << endl;
      failures.push_back(fs.str());
    } catch(IfaceExecutionError &err) {
      ostringstream fs;
      fs << "Error executing " << testFiles[i] << ": " << err.explain;
      cout << fs.str() << endl;
      failures.push_back(fs.str());
    }
  }

  cout << endl;
  cout << "Total tests applied = " << totalTestsApplied << endl;
  cout << "Total passing tests = " << totalTestsSucceeded << endl;
  cout << endl;
  if (!failures.empty()) {
    cout << "Failures: " << endl;
    list<string>::const_iterator iter = failures.begin();
    for(int4 i=0;i<10;++i) {
      cout << "  " << *iter << endl;
      ++iter;
      if (iter == failures.end()) break;
    }
  }
}
