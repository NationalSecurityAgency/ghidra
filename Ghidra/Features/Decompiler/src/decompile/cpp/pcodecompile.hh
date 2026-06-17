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
/// \file pcodecompile.hh
/// \brief Classes for compiling p-code expressions from SLEIGH or other text specifications

#ifndef __PCODECOMPILE_HH__
#define __PCODECOMPILE_HH__

#include "slghsymbol.hh"

namespace ghidra {

/// \brief A location within a specification being parsed
class Location {
  string filename;		///< Base name of the file being parsed
  int4 lineno;			///< Line number within the file
public:
  Location(void) {}		///< Construct an uninitialized location
  Location(const string &fname, const int4 line) { filename = fname; lineno = line; }	///< Constructor
  string getFilename(void) const { return filename; }	///< Get the base file name
  int4 getLineno(void) const { return lineno; }		///< Get the line number
  string format(void) const;				///< Return a text representation of \b this
};

/// \brief The address space and pointer size associated with a SLEIGH '*' operator
struct StarQuality {
  ConstTpl id;		///< The id of the address space
  uint4 size;		///< Number of bytes being LOADed or STOREd
};

/// \brief A p-code expression tree
///
/// A single connected tree of OpTpl and VarnodeTpl nodes, with either a root VarnodeTpl or a root OpTpl with no output.
/// The OpTpl are stored in the flattened order the will be emitted as.
class ExprTree {
  friend class PcodeCompile;
  vector<OpTpl *> *ops;		///< Flattened ops making up the expression
  VarnodeTpl *outvn;		///< Root VarnodeTpl: Copy of the output from the final OpTpl (or NULL)
public:
  ExprTree(void) { ops = (vector<OpTpl *> *)0; outvn = (VarnodeTpl *)0; }	///< Construct an empty expression
  ExprTree(VarnodeTpl *vn);			///< Construct an expression with a single VarnodeTpl
  ~ExprTree(void);				///< Destructor
  void setOutput(VarnodeTpl *newout);		///< Force the output of the expression to be a new VarnodeTpl
  VarnodeTpl *getOut(void) { return outvn; }	///< Get the root VarnodeTpl
  const ConstTpl &getSize(void) const { return outvn->getSize(); }	///< Get the size of the root VarnodeTpl
  static vector<OpTpl *> *appendParams(OpTpl *op,vector<ExprTree *> *param);
  static vector<OpTpl *> *toVector(ExprTree *expr);
};

/// \brief The base class for compiling p-code expressions from SLEIGH syntax
///
/// This is essentially a utility class for building OpTpl, VarnodeTpl, and their associated expressions.
/// Address spaces must be provided via the setXXXSpace() methods, so that the class can model the
/// corresponding SLEIGH concepts.
class PcodeCompile {
  AddrSpace *defaultspace;	///< SLEIGH's \e default address space
  AddrSpace *constantspace;	///< SLEIGH's \e constant address space
  AddrSpace *uniqspace;		///< SLEIGH's \e unique address space
  uint4 local_labelcount;	///< Number of labels in current constructor
  bool enforceLocalKey;		///< If \b true, force specification to use 'local' keyword when defining temporary varnodes

  /// \brief Get the offset for the next available temporary register
  ///
  /// A fixed number of bytes in the \e unique space is consumed.
  /// \return the reserved offset
  virtual uint4 allocateTemp(void)=0;

  /// \brief Add a new symbol to the current scope
  ///
  /// \param sym is the symbol being added
  virtual void addSymbol(SleighSymbol *sym)=0;
public:
  PcodeCompile(void) { defaultspace=(AddrSpace *)0; constantspace=(AddrSpace *)0;
			  uniqspace=(AddrSpace *)0; local_labelcount=0; enforceLocalKey=false; }	///< Constructor
  virtual ~PcodeCompile(void) {}						///< Destructor

  /// \brief Get the parse location associated with the given symbol
  ///
  /// This is generally where the symbol is first defined.
  /// \param sym is the given symbol
  /// \return the location if known, or NULL otherwise
  virtual const Location *getLocation(SleighSymbol *sym) const=0;

  /// \brief Report a fatal error in parsing
  ///
  /// Parsing may continue, but a final output is not produced.
  /// \param loc is the location of the error
  /// \param msg is a description of the error
  virtual void reportError(const Location *loc, const string &msg)=0;

  /// \brief Report a non-fatal issue encountered during parsing
  ///
  /// \param loc is the location of the issue
  /// \param msg is a description of the issue
  virtual void reportWarning(const Location *loc, const string &msg)=0;

  void resetLabelCount(void) { local_labelcount=0; }			///< Reset labels.  The next label generated will have id 0
  void setDefaultSpace(AddrSpace *spc) { defaultspace = spc; }		///< Set the SLEIGH \e default address space
  void setConstantSpace(AddrSpace *spc) { constantspace = spc; }	///< Set the SLEIGH \e constant address space
  void setUniqueSpace(AddrSpace *spc) { uniqspace = spc; }		///< Set the SLEIGH \e unique address space
  void setEnforceLocalKey(bool val) { enforceLocalKey = val; }		///< Toggle whether use of the 'local' key is enforced
  AddrSpace *getDefaultSpace(void) const { return defaultspace; }	///< Get the \e default address space
  AddrSpace *getConstantSpace(void) const { return constantspace; }	///< Get the \e constant address space
  VarnodeTpl *buildTemporary(void);					///< Create a temporary register (with 0 size)
  LabelSymbol *defineLabel(string *name);				///< Create a SLEIGH label symbol
  vector<OpTpl *> *placeLabel(LabelSymbol *sym);			///< Create a \e raw expression containing the given label
  vector<OpTpl *> *newOutput(bool usesLocalKey,ExprTree *rhs,string *varname,uint4 size=0);	///< Create a new output VarnodeTpl for an expression
  void newLocalDefinition(string *varname,uint4 size=0); 		///< Create a new temporary symbol (without generating any p-code)
  ExprTree *createOp(OpCode opc,ExprTree *vn);				///< Add a new unary operation to the given expression
  ExprTree *createOp(OpCode opc,ExprTree *vn1,ExprTree *vn2);		///< Create a new binary operation combining the given expressions
  ExprTree *createOpOut(VarnodeTpl *outvn,OpCode opc,ExprTree *vn1,ExprTree *vn2);
  ExprTree *createOpOutUnary(VarnodeTpl *outvn,OpCode opc,ExprTree *vn);
  vector<OpTpl *> *createOpNoOut(OpCode opc,ExprTree *vn);
  vector<OpTpl *> *createOpNoOut(OpCode opc,ExprTree *vn1,ExprTree *vn2);
  vector<OpTpl *> *createOpConst(OpCode opc,uintb val);
  ExprTree *createLoad(StarQuality *qual,ExprTree *ptr);
  vector<OpTpl *> *createStore(StarQuality *qual,ExprTree *ptr,ExprTree *val);
  ExprTree *createUserOp(UserOpSymbol *sym,vector<ExprTree *> *param);
  vector<OpTpl *> *createUserOpNoOut(UserOpSymbol *sym,vector<ExprTree *> *param);
  ExprTree *createVariadic(OpCode opc,vector<ExprTree *> *param);
  void appendOp(OpCode opc,ExprTree *res,uintb constval,int4 constsz);
  VarnodeTpl *buildTruncatedVarnode(VarnodeTpl *basevn,uint4 bitoffset,uint4 numbits);
  vector<OpTpl *> *assignBitRange(VarnodeTpl *vn,uint4 bitoffset,uint4 numbits,ExprTree *rhs);
  ExprTree *createBitRange(SpecificSymbol *sym,uint4 bitoffset,uint4 numbits);
  VarnodeTpl *addressOf(VarnodeTpl *var,uint4 size);
  static void force_size(VarnodeTpl *vt,const ConstTpl &size,const vector<OpTpl *> &ops);
  static void matchSize(int4 j,OpTpl *op,bool inputonly,const vector<OpTpl *> &ops);
  static void fillinZero(OpTpl *op,const vector<OpTpl *> &ops);
  static bool propagateSize(ConstructTpl *ct);
};

} // End namespace ghidra
#endif
