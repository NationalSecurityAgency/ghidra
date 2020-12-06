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
// Very generic command line executor class:   IfaceStatus
// A new class instance derived from IfaceCommand is attached to a command line via registerCom
// i.e.
// IfaceStatus stat(cin,cout);
// stat.registerCom(new IfcQuit(),"quit");
// stat.registerCom(new IfcOpenfileAppend(),"openfile","append");
// stat.mainloop();

// Command line processing is started with mainloop, which prints a
// prompt set with setprompt, allows bash style command line editing, including
// command completion and history, and executes the corresponding IfaceCommand.execute callback.
// Command words only have to match enough to disambiguate it from other commands.

// Custom history size can be passed in constructor to IfaceStatus.
// Applications should inherit from base class IfaceStatus in order
// to get custom data into IfaceCommand callbacks and to redefine
// the virtual function execute for custom error handling.

#ifndef __INTERFACE__
#define __INTERFACE__

#include "capability.hh"
#include <string>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cstdio>

using namespace std;

#ifdef __REMOTE_SOCKET__

/// \brief A wrapper around a UNIX domain socket
///
/// The open() command attempts to connect to given socket name,
/// which must have been previously established by an external process.
/// The socket is bound to a C++ istream and ostream.
class RemoteSocket {
  int fileDescriptor;		///< Descriptor for the socket
  basic_filebuf<char> *inbuf;	///< Input buffer associated with the socket
  basic_filebuf<char> *outbuf;	///< Output buffer for the socket
  istream *inStream;		///< The C++ input stream
  ostream *outStream;		///< The C++ output stream
  bool isOpen;			///< Has the socket been opened
public:
  RemoteSocket(void);				///< Constructor
  ~RemoteSocket(void) { close(); }		///< Destructor
  bool open(const string &filename);		///< Connect to the given socket
  bool isSocketOpen(void);			///< Return \b true if the socket is ready to transfer data
  istream *getInputStream(void) { return inStream; }	///< Get the input stream
  ostream *getOutputStream(void) { return outStream; }	///< Get the output stream
  void close(void);				///< Close the streams and socket
};

#endif

struct IfaceError {
  string explain;		// Explanatory string
  IfaceError(const string &s) { explain = s; }
};

struct IfaceParseError : public IfaceError {
  IfaceParseError(const string &s) : IfaceError(s) {}
};

struct IfaceExecutionError : public IfaceError {
  IfaceExecutionError(const string &s) : IfaceError(s) {}
};

class IfaceStatus;		// Forward declaration

class IfaceData {		// Data specialized for a particular command
public:
  virtual ~IfaceData(void) {}
};

class IfaceCommand {
  vector<string> com;		// The command
public:
  virtual ~IfaceCommand(void) {}
  virtual void setData(IfaceStatus *root,IfaceData *data)=0;
  virtual void execute(istream &s)=0;
  virtual string getModule(void) const=0;
  virtual IfaceData *createData(void)=0;
  void addWord(const string &temp) { com.push_back(temp); }
  void removeWord(void) { com.pop_back(); }
  const string &getCommandWord(int4 i) const { return com[i]; }
  void addWords(const vector<string> &wordlist);
  int4 numWords(void) const { return com.size(); }
  void commandString(string &res) const;
  int4 compare(const IfaceCommand &op2) const;
};

class IfaceCommandDummy : public IfaceCommand {
public:
  virtual void setData(IfaceStatus *root,IfaceData *data) {}
  virtual void execute(istream &s) {}
  virtual string getModule(void) const { return "dummy"; }
  virtual IfaceData *createData(void) { return (IfaceData *)0; }
};

inline bool compare_ifacecommand(const IfaceCommand *a,const IfaceCommand *b) {
  return (0>a->compare(*b));
}

class IfaceCapability : public CapabilityPoint {
  static vector<IfaceCapability *> thelist;
protected:
  string name;			// Identifying name for the capability
public:
  const string &getName(void) const { return name; }
  virtual void initialize(void);
  virtual void registerCommands(IfaceStatus *status)=0;

  static void registerAllCommands(IfaceStatus *status);
};

class IfaceStatus {
  vector<istream *> inputstack;
  vector<string> promptstack;
  vector<uint4> flagstack;
  string prompt;
  int4 maxhistory;
  int4 curhistory;		// most recent history
  vector<string> history;
  bool sorted;			// Are commands sorted
  bool inerror;			// -true- if last command did not succeed
  bool errorisdone;		// -true- if any error terminates the process
  void restrict(vector<IfaceCommand *>::const_iterator &first,vector<IfaceCommand *>::const_iterator &last,vector<string> &input);
  virtual void readLine(string &line) { getline(*sptr,line,'\n'); }
  void saveHistory(const string &line);
protected:
  istream *sptr;		// Where to get input
  vector<IfaceCommand *> comlist; // List of commands
  map<string,IfaceData *> datamap; // Data associated with particular modules
  int4 expandCom(vector<string> &expand,istream &s,
		vector<IfaceCommand *>::const_iterator &first,
		vector<IfaceCommand *>::const_iterator &last);
public:
  bool done;
  ostream *optr;		// Where to put command line output
  ostream *fileoptr;		// Where to put bulk output

  IfaceStatus(const string &prmpt,istream &is,ostream &os,int4 mxhist=10);
  virtual ~IfaceStatus(void);
  void setErrorIsDone(bool val) { errorisdone = val; }
  void pushScript(const string &filename,const string &newprompt);
  void popScript(void);
  void reset(void);
  int4 getNumInputStreamSize(void) const { return inputstack.size(); }
  void writePrompt(void) { *optr << prompt; }
  void registerCom(IfaceCommand *fptr, const char *nm1,
		   const char *nm2 = (const char *)0,
		   const char *nm3 = (const char *)0,
		   const char *nm4 = (const char *)0,
		   const char *nm5 = (const char *)0);
  IfaceData *getData(const string &nm) const;
  bool runCommand(void);
  void getHistory(string &line,int4 i) const;
  int4 getHistorySize(void) const { return history.size(); }
  bool isStreamFinished(void) const { if (done||inerror) return true; return sptr->eof(); }
  bool isInError(void) const { return inerror; }
  void evaluateError(void);
  static void wordsToString(string &res,const vector<string> &list);
};

class IfaceBaseCommand : public IfaceCommand {
protected:
  IfaceStatus *status;
public:
  virtual void setData(IfaceStatus *root,IfaceData *data) { status = root; }
  virtual string getModule(void) const { return "base"; }
  virtual IfaceData *createData(void) { return (IfaceData *)0; }
};

class IfcQuit : public IfaceBaseCommand {
public:
  virtual void execute(istream &s);
};

class IfcHistory : public IfaceBaseCommand {
public:
  virtual void execute(istream &s);
};

class IfcOpenfile : public IfaceBaseCommand {
public:
  virtual void execute(istream &s);
};

class IfcOpenfileAppend : public IfaceBaseCommand {
public:
  virtual void execute(istream &s);
};

class IfcClosefile : public IfaceBaseCommand {
public:
  virtual void execute(istream &s);
};

class IfcEcho : public IfaceBaseCommand {
public:
  virtual void execute(istream &s);
};

#endif
