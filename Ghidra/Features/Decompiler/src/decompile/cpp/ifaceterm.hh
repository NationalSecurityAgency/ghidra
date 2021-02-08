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
/// \file ifaceterm.hh
/// \brief Add some terminal capabilities to the command-line interface (IfaceStatus)

#include "interface.hh"

#ifdef __TERMINAL__
extern "C" {
#include <termios.h>
#include <errno.h>
}
#endif

/// \brief Implement the command-line interface on top of a specific input stream
///
/// An initial input stream is provided as the base stream to parse for commands.
/// Additional input streams can be stacked by invoking scripts.
/// If the stream supports it, the stream parser recognizes special command-line editing
/// and completion keys.
class IfaceTerm : public IfaceStatus {
#ifdef __TERMINAL__
  bool is_terminal;		///< True if the input stream is a terminal
  int4 ifd;			///< Underlying file descriptor
  struct termios itty;		///< Original terminal settings
#endif
  istream *sptr;		///< The base input stream for the interface
  vector<istream *> inputstack;	///< Stack of nested input streams
  int4 doCompletion(string &line,int4 cursor);	///< 'Complete' the current command line
  virtual void readLine(string &line);
public:
  IfaceTerm(const string &prmpt,istream &is,ostream &os);	///< Constructor
  virtual ~IfaceTerm(void);
  virtual void pushScript(const string &filename,const string &newprompt);
  virtual void popScript(void);
  virtual bool isStreamFinished(void) const;
};
