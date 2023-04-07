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
#ifndef __PCODEPARSE_HH__
#define __PCODEPARSE_HH__

#include "pcodecompile.hh"
#include "sleighbase.hh"

namespace ghidra {

// Classes for compiling a standalone snippet of pcode, given an existing sleigh language

struct IdentRec {
  const char *nm;
  int4 id;
};

class PcodeLexer {
public:
  enum {			// Lexer states
    start,
    special2,			// Middle of special 2 character operator
    special3,                   // First character of special 3 character operator
    special32,			// Second character of special 3 character operator
    comment,			// Middle of an endofline comment
    punctuation,		// Punctuation character
    identifier,			// Middle of an identifier
    hexstring,			// Middle of a hexidecimal number
    decstring,			// Middle of a decimal number
    endstream,			// Reached end of stream
    illegal			// Scanned an illegal character
  };
private:
  static const IdentRec idents[];
  int4 curstate;
  char curchar,lookahead1,lookahead2;
  char curtoken[256];
  int4 tokpos;
  bool endofstream;
  bool endofstreamsent;
  istream *s;
  string curidentifier;
  uintb curnum;
  void starttoken(void) { curtoken[0] = curchar; tokpos = 1; }
  void advancetoken(void) { curtoken[tokpos++] = curchar; }
  bool isIdent(char c) const { return (isalnum(c)||(c=='_')||(c=='.')); }
  bool isHex(char c) const { return isxdigit(c); }
  bool isDec(char c) const { return isdigit(c); }
  int4 findIdentifier(const string &str) const;
  int4 moveState(void);
public:
  PcodeLexer(void) { s = (istream *)0; }
  void initialize(istream *t);
  int4 getNextToken(void);
  const string &getIdentifier(void) const { return curidentifier; }
  uintb getNumber(void) const { return curnum; }
};

class PcodeSnippet : public PcodeCompile {
  PcodeLexer lexer;
  const SleighBase *sleigh;	// Language from which we get symbols
  SymbolTree tree;		// Symbols in the local scope of the snippet  (temporaries)
  uint4 tempbase;
  int4 errorcount;
  string firsterror;
  ConstructTpl *result;
  virtual uint4 allocateTemp(void);
  virtual void addSymbol(SleighSymbol *sym);
public:  
  PcodeSnippet(const SleighBase *slgh);
  void setResult(ConstructTpl *res) { result = res; }
  ConstructTpl *releaseResult(void) { ConstructTpl *res = result; result = (ConstructTpl *)0; return res; }
  virtual ~PcodeSnippet(void);
  virtual const Location *getLocation(SleighSymbol *sym) const { return (const Location *)0; }
  virtual void reportError(const Location *loc, const string &msg);
  virtual void reportWarning(const Location *loc, const string &msg) {}
  bool hasErrors(void) const { return (errorcount != 0); }
  const string getErrorMessage(void) const { return firsterror; }
  void setUniqueBase(uint4 val) { tempbase = val; }
  uint4 getUniqueBase(void) const { return tempbase; }
  void clear(void);
  int lex(void);
  bool parseStream(istream& s);
  void addOperand(const string &name,int4 index);
};

} // End namespace ghidra
#endif
