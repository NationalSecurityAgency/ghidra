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
/// \file interface.hh
/// \brief Classes and utilities for a \e generic command-line interface

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

/// \brief An exception specific to the command line interface
struct IfaceError {
  string explain;		///< Explanatory string
  IfaceError(const string &s) { explain = s; }	///< Constructor
};

/// \brief An exception describing a parsing error in a command line
///
/// Thrown when attempting to parse a command line.  Options are missing or are in
/// the wrong form etc.
struct IfaceParseError : public IfaceError {
  IfaceParseError(const string &s) : IfaceError(s) {}	///< Constructor
};

/// \brief An exception throw during the execution of a command
///
/// Processing of a specific command has started but has reached an error state
struct IfaceExecutionError : public IfaceError {
  IfaceExecutionError(const string &s) : IfaceError(s) {}	///< Constructor
};

class IfaceStatus;		// Forward declaration

/// \brief Data specialized for a particular command module
///
/// IfaceCommands can have specialized data that is shared with other commands in
/// the same module.  This is the root object for all such data.
class IfaceData {
public:
  virtual ~IfaceData(void) {}		///< Destructor
};

/// \brief A command that can be executed from the command line
///
/// The command has data associated with it (via setData()) and is executed
/// via the execute() method.  The command can get additional parameters from
/// the command line by reading the input stream passed to it.
/// The command is associated with a specific sequence of words (tokens)
/// that should appear at the start of the command line.
class IfaceCommand {
  vector<string> com;		///< The token sequence associated with the command
public:
  virtual ~IfaceCommand(void) {}	///< Destructor

  /// \brief Associate a specific data object with this command.
  ///
  /// \param root is the interface object this command is registered with
  /// \param data is the data object the command should use
  virtual void setData(IfaceStatus *root,IfaceData *data)=0;

  /// Execute this command. Additional state can be read from the given command line stream.
  /// Otherwise, the command gets its data from its registered IfaceData object
  /// \param s is the input stream from the command line
  virtual void execute(istream &s)=0;

  /// \brief Get the formal module name to which this command belongs
  ///
  /// Commands in the same module share data through their registered IfaceData object
  /// \return the formal module name
  virtual string getModule(void) const=0;

  /// \brief Create a specialized data object for \b this command (and its module)
  ///
  /// This method is only called once per module
  /// \return the newly created data object for the module
  virtual IfaceData *createData(void)=0;

  /// \brief Add a token to the command line string associated with this command
  ///
  /// \param temp is the new token to add
  void addWord(const string &temp) { com.push_back(temp); }

  void removeWord(void) { com.pop_back(); }	///< Remove the last token from the associated command line string
  const string &getCommandWord(int4 i) const { return com[i]; }	///< Get the i-th command token
  void addWords(const vector<string> &wordlist);	///< Add words to the associated command line string
  int4 numWords(void) const { return com.size(); }	///< Return the number of tokens in the command line string
  void commandString(string &res) const;	///< Get the complete command line string
  int4 compare(const IfaceCommand &op2) const;	///< Order two commands by their command line strings
};

/// \brief A dummy command used during parsing
class IfaceCommandDummy : public IfaceCommand {
public:
  virtual void setData(IfaceStatus *root,IfaceData *data) {}
  virtual void execute(istream &s) {}
  virtual string getModule(void) const { return "dummy"; }
  virtual IfaceData *createData(void) { return (IfaceData *)0; }
};

/// \brief Compare to commands as pointers
///
/// \param a is a pointer to the first command
/// \param b is a pointer to the second command
/// \return \b true if the first pointer is ordered before the second
inline bool compare_ifacecommand(const IfaceCommand *a,const IfaceCommand *b) {
  return (0>a->compare(*b));
}

/// \brief Groups of console commands that are \e discovered by the loader
///
/// Any IfaceCommand that is registered with a grouping derived from this class
/// is automatically made available to any IfaceStatus object just by calling
/// the static registerAllCommands()
class IfaceCapability : public CapabilityPoint {
  static vector<IfaceCapability *> thelist;	///< The global list of discovered command groupings
protected:
  string name;			///< Identifying name for the capability
public:
  const string &getName(void) const { return name; }	///< Get the name of the capability
  virtual void initialize(void);
  virtual void registerCommands(IfaceStatus *status)=0; ///< Register commands for \b this grouping

  static void registerAllCommands(IfaceStatus *status);	///< Register all discovered commands with the interface
};

/// \brief A generic console mode interface and command executor
///
/// Input is provided one  command line at a time by providing calling readLine().
/// Output goes to a provided ostream, \e optr.   Output to a separate bulk stream
/// can be enabled by setting \e fileoptr.
///
/// A derived IfaceCommand is attached to a command string via registerCom()
/// i.e.
/// stat.registerCom(new IfcQuit(),"quit");
/// stat.registerCom(new IfcOpenfileAppend(),"openfile","append");
/// stat.mainloop();

/// Command line processing is started with mainloop(), which prints a command prompt,
/// allows command line editing, including command completion and history, and executes
/// the corresponding IfaceComman::execute() callback.
/// Command words only have to match enough to disambiguate it from other commands.

/// A Custom history size and command prompt can be passed to the constructor.
/// Applications should inherit from base class IfaceStatus in order to
///   - Override the readLine() method
///   - Override pushScript() and popScript() to allow command scripts
///   - Get custom data into IfaceCommand callbacks
class IfaceStatus {
  vector<string> promptstack;	///< Stack of command prompts corresponding to script nesting level
  vector<uint4> flagstack;	///< Stack of flag state corresponding to script nesting level
  string prompt;		///< The current command prompt
  int4 maxhistory;		///< Maximum number of command lines to store in history
  int4 curhistory;		///< Most recent history
  vector<string> history;	///< History of commands executed through this interface
  bool sorted;			///< Set to \b true if commands are sorted
  bool errorisdone;		///< Set to \b true if any error terminates the process
  void restrictCom(vector<IfaceCommand *>::const_iterator &first,
		   vector<IfaceCommand *>::const_iterator &last,vector<string> &input);

  /// \brief Read the next command line
  ///
  /// \param line is filled in with the next command to execute
  virtual void readLine(string &line)=0;
  void saveHistory(const string &line);		///< Store the given command line into \e history
protected:
  bool inerror;			///< Set to \b true if last command did not succeed
  vector<IfaceCommand *> comlist; ///< List of registered commands
  map<string,IfaceData *> datamap; ///< Data associated with particular modules
  int4 expandCom(vector<string> &expand,istream &s,
		vector<IfaceCommand *>::const_iterator &first,
		vector<IfaceCommand *>::const_iterator &last);
public:
  bool done;			///< Set to \b true (by a command) to indicate processing is finished
  ostream *optr;		///< Where to put command line output
  ostream *fileoptr;		///< Where to put bulk output

  IfaceStatus(const string &prmpt,ostream &os,int4 mxhist=10);	///< Constructor
  virtual ~IfaceStatus(void);					///< Destructor
  void setErrorIsDone(bool val) { errorisdone = val; }	///< Set if processing should terminate on an error
  virtual void pushScript(const string &filename,const string &newprompt);
  virtual void popScript(void);
  void reset(void);	///< Pop any existing script streams and return to processing from the base stream
  int4 getNumInputStreamSize(void) const { return promptstack.size(); }	///< Get depth of script nesting
  void writePrompt(void) { *optr << prompt; }	///< Write the current command prompt to the current output stream
  void registerCom(IfaceCommand *fptr, const char *nm1,
		   const char *nm2 = (const char *)0,
		   const char *nm3 = (const char *)0,
		   const char *nm4 = (const char *)0,
		   const char *nm5 = (const char *)0);
  IfaceData *getData(const string &nm) const;	///< Get data associated with a IfaceCommand module
  bool runCommand(void);			///< Run the next command
  void getHistory(string &line,int4 i) const;	///< Get the i-th command line from history
  int4 getHistorySize(void) const { return history.size(); }	///< Get the number of command lines in history
  virtual bool isStreamFinished(void) const=0;		///< Return \b true if the current stream is finished
  bool isInError(void) const { return inerror; }	///< Return \b true if the last command failed
  void evaluateError(void);			///< Adjust which stream to process based on last error
  static void wordsToString(string &res,const vector<string> &list);	///< Concatenate tokens
};

/// \brief A root class for a basic set of commands
///
/// Commands derived from this class are in the "base" module.
/// They are useful as part of any interface
class IfaceBaseCommand : public IfaceCommand {
protected:
  IfaceStatus *status;		///< The interface owning this command instance
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
