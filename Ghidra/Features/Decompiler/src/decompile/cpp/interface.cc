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
#include "interface.hh"
#ifdef __REMOTE_SOCKET__
#include "sys/socket.h"
#include "sys/un.h"
#include "unistd.h"
#include "ext/stdio_filebuf.h"
#endif

vector<IfaceCapability *> IfaceCapability::thelist;

void IfaceCapability::initialize(void)

{
  thelist.push_back(this);
}

void IfaceCapability::registerAllCommands(IfaceStatus *status)

{ // Allow each capability to register its own commands
  for(uint4 i=0;i<thelist.size();++i)
    thelist[i]->registerCommands(status);
}

#ifdef __REMOTE_SOCKET__

RemoteSocket::RemoteSocket(void)

{
  fileDescriptor = 0;
  inbuf = (basic_filebuf<char> *)0;
  outbuf = (basic_filebuf<char> *)0;
  inStream = (istream *)0;
  outStream = (ostream *)0;
  isOpen = false;
}

void RemoteSocket::close(void)

{
  if (inStream != (istream *)0) {
    delete inStream;
    inStream = (istream *)0;
  }
  if (outStream != (ostream *)0) {
    delete outStream;
    outStream = (ostream *)0;
  }
  if (inbuf != (basic_filebuf<char> *)0) {
    // Destroying the buffer should automatically close the socket
    delete inbuf;
    inbuf = (basic_filebuf<char> *)0;
  }
  if (outbuf != (basic_filebuf<char> *)0) {
    delete outbuf;
    outbuf = (basic_filebuf<char> *)0;
  }
  isOpen = false;
}

bool RemoteSocket::open(const string &filename)

{
  if (isOpen) return false;
  if ((fileDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    throw IfaceError("Could not create socket");
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  int4 len = filename.length();
  if (len >= sizeof(addr.sun_path))
    throw IfaceError("Socket name too long");
  memcpy(addr.sun_path,filename.c_str(),len);
  addr.sun_path[len] = '\0';
  len += sizeof(addr.sun_family);
  if (connect(fileDescriptor, (struct sockaddr *)&addr, len) < 0) {
    ::close(fileDescriptor);
    return false;
  }

  fdopen(fileDescriptor, "r");
  inbuf = new __gnu_cxx::stdio_filebuf<char>(fileDescriptor,ios::in);
  fdopen(fileDescriptor, "w");
  outbuf = new __gnu_cxx::stdio_filebuf<char>(fileDescriptor,ios::out);
  inStream = new istream(inbuf);
  outStream = new ostream(outbuf);
  isOpen = true;
  return true;
}

bool RemoteSocket::isSocketOpen(void)

{
  if (!isOpen) return false;
  if (inStream->eof()) {
    close();
    return false;
  }
  return true;
}

#endif

IfaceStatus::IfaceStatus(const string &prmpt,istream &is,ostream &os,int4 mxhist)

{
  sptr = &is;
  optr = &os;
  fileoptr = optr;		// Bulk out, defaults to command line output
  sorted = false;
  inerror = false;
  errorisdone = false;
  done = false;
  prompt = prmpt;
  maxhistory = mxhist;
  curhistory = 0;
}

void IfaceStatus::pushScript(const string &filename,const string &newprompt)

{ // Push new input stream on stack (with new prompt)
  ifstream *s = new ifstream(filename.c_str());
  if (!*s)
    throw IfaceParseError("Unable to open script file");
  inputstack.push_back(sptr);
  promptstack.push_back(prompt);
  uint4 flags = 0;
  if (errorisdone)
    flags |= 1;
  flagstack.push_back(flags);
  sptr = s;
  prompt = newprompt;
}

void IfaceStatus::popScript(void)

{ // Pop the current input stream (and current prompt)
  delete sptr;
  sptr = inputstack.back();
  inputstack.pop_back();
  prompt = promptstack.back();
  promptstack.pop_back();
  uint4 flags = flagstack.back();
  flagstack.pop_back();
  errorisdone = ((flags & 1)!=0);
  inerror = false;
}

void IfaceStatus::reset(void)

{
  while(!inputstack.empty())
    popScript();
  errorisdone = false;
  done = false;
}

void IfaceStatus::saveHistory(const string &line)

{				// Save line in circular history buffer
  if (history.size() < maxhistory)
    history.push_back(line);
  else
    history[curhistory] = line;
  curhistory += 1;
  if (curhistory == maxhistory)
    curhistory = 0;
}

void IfaceStatus::getHistory(string &line,int4 i) const

{
  if (i>=history.size())
    return; // No change to line if history too far back

  i = curhistory-1-i;
  if (i<0) i+= maxhistory;
  line = history[i];
}

void IfaceStatus::evaluateError(void)

{ // The last command has failed, decide if we are completely abandoning this stream
  if (errorisdone) {
    *optr << "Aborting process" << endl;
    inerror = true;
    done = true;
    return;
  }
  if (getNumInputStreamSize()!=0) { // we have something to pop
    *optr << "Aborting " << prompt << endl;
    inerror = true;
    return;
  }
  inerror = false;
}

void IfaceStatus::wordsToString(string &res,const vector<string> &list)

{
  vector<string>::const_iterator iter;

  res.erase();
  for(iter=list.begin();iter!=list.end();++iter) {
    if (iter != list.begin())
      res += ' ';
    res += *iter;
  }
}

IfaceStatus::~IfaceStatus(void)

{
  if (optr != fileoptr) {
    ((ofstream *)fileoptr)->close();
    delete fileoptr;
  }
  while(!inputstack.empty())
    popScript();
  for(int4 i=0;i<comlist.size();++i)
    delete comlist[i];
  map<string,IfaceData *>::const_iterator iter;
  for(iter=datamap.begin();iter!=datamap.end();++iter)
    if ((*iter).second != (IfaceData *)0)
      delete (*iter).second;
}

void IfaceStatus::registerCom(IfaceCommand *fptr,const char *nm1,
			      const char *nm2,
			      const char *nm3,
			      const char *nm4,
			      const char *nm5)

{				// Register an interface command
  fptr->addWord(nm1);
  if (nm2 != (const char *)0)
    fptr->addWord(nm2);
  if (nm3 != (const char *)0)
    fptr->addWord(nm3);
  if (nm4 != (const char *)0)
    fptr->addWord(nm4);
  if (nm5 != (const char *)0)
    fptr->addWord(nm5);

  comlist.push_back(fptr);	// Enter new command
  sorted = false;

  const string &nm( fptr->getModule() ); // Name of module this command belongs to
  map<string,IfaceData *>::const_iterator iter = datamap.find( nm );
  IfaceData *data;
  if (iter == datamap.end()) {
    data = fptr->createData();
    datamap[nm] = data;
  }
  else
    data = (*iter).second;
  fptr->setData(this,data);	// Inform command of its data
}

IfaceData *IfaceStatus::getData(const string &nm) const

{				// Get data corresponding to the named module
  map<string,IfaceData *>::const_iterator iter = datamap.find(nm);
  if (iter == datamap.end())
    return (IfaceData *)0;
  return (*iter).second;
}

bool IfaceStatus::runCommand(void)

{
  string line;			// Next line from input stream

  if (!sorted) {
    sort(comlist.begin(),comlist.end(),compare_ifacecommand);
    sorted = true;
  }
  readLine(line);
  if (line.empty()) return false;
  saveHistory(line);

  vector<string> fullcommand;
  vector<IfaceCommand *>::const_iterator first = comlist.begin();
  vector<IfaceCommand *>::const_iterator last = comlist.end();
  istringstream is(line);
  int4 match;

  match = expandCom(fullcommand, is,first,last); // Try to expand the command
  if (match == 0) {
    *optr << "ERROR: Invalid command" << endl;
    return false;
  }
  else if ( fullcommand.size() == 0 ) // Nothing useful typed
    return false;
  else if (match>1) {
    if ( (*first)->numWords() != fullcommand.size()) { // Check for complete but not unique
      *optr << "ERROR: Incomplete command" << endl;
      return false;
    }
  }
  else if (match<0)
    *optr << "ERROR: Incomplete command" << endl;

  (*first)->execute(is);	// Try to execute the (first) command
  return true;			// Indicate a command was executed
}

void IfaceStatus::restrict(vector<IfaceCommand *>::const_iterator &first,
			   vector<IfaceCommand *>::const_iterator &last,
			   vector<string> &input)

{
  vector<IfaceCommand *>::const_iterator newfirst,newlast;
  IfaceCommandDummy dummy;
  
  dummy.addWords(input);
  newfirst = lower_bound(first,last,&dummy,compare_ifacecommand);
  dummy.removeWord();
  string temp( input.back() );	// Make copy of last word
  temp[ temp.size()-1 ] += 1;	// temp will now be greater than any word
				// whose first letters match input.back()
  dummy.addWord(temp);
  newlast = upper_bound(first,last,&dummy,compare_ifacecommand);
  first = newfirst;
  last = newlast;
}

static bool maxmatch(string &res,const string &op1,const string &op2)

{				// Set res to maximum characters in common
				// at the beginning of op1 and op2
  int4 len;
  bool equal;

  if (op1.size() == op2.size()) {
    len = op1.size();
    equal = true;
  }
  else {
    equal = false;
    len = ( op1.size() < op2.size() ) ? op1.size() : op2.size();
  }

  res.erase();
  for(int4 i=0;i<len;++i) {
    if (op1[i] == op2[i])
      res += op1[i];
    else
      return false;
  }
  return equal;
}

int4 IfaceStatus::expandCom(vector<string> &expand,istream &s,
			   vector<IfaceCommand *>::const_iterator &first,
			   vector<IfaceCommand *>::const_iterator &last)

{				// Expand tokens on stream to full command
				// Return range of possible commands
				// If command is complete with extra arguments
				//  return (dont process) remaining args
				// Return number of matching commands

  int4 pos;			// Which word are we currently expanding
  string tok;
  bool res;

  expand.clear();		// Make sure command list is empty
  res = true;
  if (first == last)		// If subrange is empty, return 0
    return 0;
  for(pos=0;;++pos) {
    s >> ws;			// Skip whitespace
    if (first == (last-1)) {	// If subrange is unique
      if (s.eof())		// If no more input
	for(;pos<(*first)->numWords();++pos) // Automatically provide missing words
	  expand.push_back( (*first)->getCommandWord(pos) );
      if ((*first)->numWords() == pos) // If all words are matched
	return 1;		// Finished
    }
    if (!res) {			// Last word was ambiguous
      if (!s.eof())
	return (last-first);
      return (first-last);	// Negative number to indicate last word incomplete
    }
    if (s.eof()) {		// if no other words
      if (expand.empty())
	return (first-last);
      return (last-first);	// return number of matches
    }
    s >> tok;			// Get next token
    expand.push_back(tok);
    restrict(first,last,expand);
    if (first == last)		// If subrange is empty, return 0
      return 0;
    res = maxmatch(tok, (*first)->getCommandWord(pos), (*(last-1))->getCommandWord(pos));
    expand.back() = tok;
  }
}

void IfaceCommand::addWords(const vector<string> &wordlist)

{
  vector<string>::const_iterator iter;

  for(iter=wordlist.begin();iter!=wordlist.end();++iter)
    com.push_back( *iter );
}

int4 IfaceCommand::compare(const IfaceCommand &op2) const

{				// Sort command based on names
  int4 res;
  vector<string>::const_iterator iter1,iter2;

  for(iter1=com.begin(),iter2=op2.com.begin();;++iter1,++iter2) {
    if (iter1 == com.end()) {
      if (iter2 == op2.com.end())
	return 0;
      return -1;		// This is less
    }
    if (iter2 == op2.com.end())
      return 1;
    res = (*iter1).compare( *iter2 );
    if (res != 0)
      return res;
  }
  return 0;			// Never reaches here
}

void IfaceCommand::commandString(string &res) const

{
  IfaceStatus::wordsToString(res,com);
}

void IfcQuit::execute(istream &s)

{				// Generic quit call back
  if (!s.eof())
    throw IfaceParseError("Too many parameters to quit");

  status->done = true;		// Set flag to drop out of mainloop
}

void IfcHistory::execute(istream &s)

{				// List most recent command lines
  int4 num;
  string historyline;

  if (!s.eof()) {
    s >> num >> ws;
    if (!s.eof())
      throw IfaceParseError("Too many parameters to history");
  }
  else
    num = 10;			// Default number of history lines

  if (num > status->getHistorySize())
    num = status->getHistorySize();

  for(int4 i=num-1;i>=0;--i) {	// List oldest to newest
    status->getHistory(historyline,i);
    *status->optr << historyline << endl;
  }
}

void IfcOpenfile::execute(istream &s)

{
  string filename;

  if (status->optr != status->fileoptr)
    throw IfaceExecutionError("Output file already opened");
  s >> filename;
  if (filename.empty())
    throw IfaceParseError("No filename specified");

  status->fileoptr = new ofstream;
  ((ofstream *)status->fileoptr)->open(filename.c_str());
  if (!*status->fileoptr) {
    delete status->fileoptr;
    status->fileoptr = status->optr;
    throw IfaceExecutionError("Unable to open file: "+filename);
  }
}

void IfcOpenfileAppend::execute(istream &s)

{
  string filename;

  if (status->optr != status->fileoptr)
    throw IfaceExecutionError("Output file already opened");
  s >> filename;
  if (filename.empty())
    throw IfaceParseError("No filename specified");

  status->fileoptr = new ofstream;
  ((ofstream *)status->fileoptr)->open(filename.c_str(),ios_base::app); // Open for appending
  if (!*status->fileoptr) {
    delete status->fileoptr;
    status->fileoptr = status->optr;
    throw IfaceExecutionError("Unable to open file: "+filename);
  }
}

void IfcClosefile::execute(istream &s)

{
  if (status->optr == status->fileoptr)
    throw IfaceExecutionError("No file open");
  ((ofstream *)status->fileoptr)->close();
  delete status->fileoptr;
  status->fileoptr = status->optr;
}

void IfcEcho::execute(istream &s)

{				// Echo command line to fileoptr
  char c;

  while(s.get(c))
    status->fileoptr->put(c);
  *status->fileoptr << endl;
}
