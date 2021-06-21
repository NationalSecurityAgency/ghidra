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
#include "ifaceterm.hh"

IfaceTerm::IfaceTerm(const string &prmpt,istream &is,ostream &os)
  : IfaceStatus(prmpt,os)
{
  sptr = &is;
#ifdef __TERMINAL__
  struct termios ittypass;

  is_terminal = true;
  //  ifd = fileno( (FILE *)sptr->rdbuf() );
  ifd = 0;			// The above line doesn't work on some systems
				// and since ifd will almost always refer to stdin...
  
  if (0>tcgetattr(ifd,&itty)) { // Get original terminal settings 
    if (errno == EBADF)
      throw IfaceError("Bad input file descriptor passed to iface");
    else if (errno == ENOTTY) {
      is_terminal = false;
      return;
    }
    throw IfaceError("Unknown error with input file stream");
  }
                              // Build terminal settings for entering passphrase 
  ittypass = itty;
  ittypass.c_lflag &= ~((tcflag_t)ECHO); // Turn off echo 
  ittypass.c_lflag &= ~((tcflag_t)ICANON); // Turn of buffered input 
  ittypass.c_cc[VMIN] = 1;    // Buffer only one character at a time 
  ittypass.c_cc[VTIME] = 0;   // Do not time out 

  if (0>tcsetattr(ifd,TCSANOW,&ittypass))
    throw IfaceError("Unable to set terminal attributes");
#endif
}

IfaceTerm::~IfaceTerm(void)

{
#ifdef __TERMINAL__
  if (is_terminal) {
    tcsetattr(ifd,TCSANOW,&itty); // Restore original terminal settings
  }
#endif
}

/// Respond to a TAB key press and try to 'complete' any existing tokens.
/// The method is handed the current state of the command-line in a string, and
/// it updates the command-line in place.
///
/// \param line is current command-line and will hold the final completion
/// \param cursor is the current position of the cursor
/// \return the (possibly new) position of the cursor, after completion
int4 IfaceTerm::doCompletion(string &line,int4 cursor)

{
  vector<string> fullcommand;
  istringstream s(line);
  string tok;
  vector<IfaceCommand *>::const_iterator first,last;
  int4 oldsize,match;

  first = comlist.begin();
  last = comlist.end();
  match = expandCom(fullcommand,s,first,last); // Try to expand the command
  if (match == 0) {
    *optr << endl << "Invalid command" << endl;
    return cursor;		// No change to command line
  }

				// At least one match
  oldsize = line.size();
  wordsToString(line,fullcommand);
  if (match<0)
    match = -match;
  else
    line += ' ';		// Provide extra space if command word is complete
  if (!s.eof()) {		// Read any additional parameters back to command line
    s >> tok >> ws;
    line += tok;		// Assume first space is present before extra params
  }
  while(!s.eof()) {
    line += ' ';		// Provide space between extra parameters
    s >> tok >> ws;
    line += tok;
  }
  if (oldsize < line.size())	// If we have expanded at all
    return line.size();		// Just display expansion
  
  if (match > 1) {		// If more than one possible command
    string complete;		// Display all possible completions
    *optr << endl;
    for(;first!=last;++first) {
      (*first)->commandString(complete); // Get possible completion
      *optr << complete << endl;
    }
  }
  else				// Command is unique and expanded
    *optr << endl << "Command is complete" << endl;
  return line.size();
}
  
void IfaceTerm::readLine(string &line)

{
  char val;
  int4 escval;
  int4 cursor,lastlen,i;
  bool onecharecho;
  int4 hist;
  string saveline;

  line.erase();
  cursor = 0;
  hist = 0;
  do {
    onecharecho = false;
    lastlen = line.size();
    val = sptr->get();
    if (sptr->eof())
      val = '\n';
    switch(val) {
    case 0x01:			// C-a
      cursor = 0;		// Jump to beginning
      break;
    case 0x02:			// C-b
      if (cursor>0)
	cursor -= 1;		// back up one char
      break;
    case 0x03:			// C-c
      line.erase();		// As if we cleared the line and hit return
      cursor = 0;
      val = 0x0a;
      onecharecho = true;
      break;
    case 0x04:			// C-d
      line.erase(cursor,1);	// Delete character cursor is on
      break;
    case 0x05:			// C-e
      cursor = line.size();	// Jump to end
      break;
    case 0x06:			// C-f
      if (cursor < line.size())
	cursor += 1;		// Move forward one character
      break;
    case 0x07:			// C-g
      break;			// do nothing
    case 0x09:			// TAB
      cursor = doCompletion(line,cursor);
      break;
    case 0x0a:			// Newline
    case 0x0d:			// Carriage return
      cursor = line.size();
      onecharecho = true;
      break;
    case 0x0b:			// C-k
      line.erase(cursor);
      break;
    case 0x0c:			// C-l
      break;
    case 0x0e:			// C-n
      if (hist >0) {
	hist -= 1;		// Get more recent history
	if (hist>0)
	  getHistory(line,hist-1);
	else
	  line = saveline;
	cursor = line.size();
      }
      break;
    case 0x10:			// C-p
      if (hist < getHistorySize()) { 
	hist += 1;		// Get more ancient history
	if (hist==1)
	  saveline = line;
	getHistory(line,hist-1);
	cursor = line.size();
      }
      break;
    case 0x12:			// C-r
      break;
    case 0x15:			// C-u
      line.erase(0,cursor);	// Erase up to cursor
      cursor = 0;
      break;
    case 0x1b:			// Escape character
      escval = sptr->get();
      escval <<= 8;
      escval += sptr->get();
      switch(escval) {
      case 0x4f44:		// left arrow
	if (cursor>0)
	  cursor -= 1;
	break;
      case 0x4f43:		// right arrow
	if (cursor<line.size())
	  cursor += 1;
	break;
      }
      break;
    case 0x08:
    case 0x7f:			// delete
      if (cursor!=0)
	line.erase(--cursor,1);
      break;
    default:
      line.insert(cursor++,1,val); // Insert single character
      if (cursor == line.size())
	onecharecho = true;
      break;
    }
    if (onecharecho)
      optr->put(val);		// Echo most characters
    else {
      optr->put('\r');		// Ontop of old line
      writePrompt();
      *optr << line;		// print new line
      for(i=line.size();i<lastlen;++i)
	optr->put(' ');		// Erase any old characters
      for(i=i-cursor;i>0;--i)
	optr->put('\b');	// Put cursor in the right place
    }
  } while(val != '\n');
}

void IfaceTerm::pushScript(const string &filename,const string &newprompt)

{
  ifstream *s = new ifstream(filename.c_str());
  if (!*s)
    throw IfaceParseError("Unable to open script file");
  inputstack.push_back(sptr);
  sptr = s;
  IfaceStatus::pushScript(filename,newprompt);
}

void IfaceTerm::popScript(void)

{
  delete sptr;
  sptr = inputstack.back();
  inputstack.pop_back();
}

bool IfaceTerm::isStreamFinished(void) const

{
  if (done||inerror) return true;
  return sptr->eof();
}
