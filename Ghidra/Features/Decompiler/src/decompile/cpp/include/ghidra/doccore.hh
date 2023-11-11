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
/** \page coreclasses Core Classes

  \section coreintro Introduction

  The decompiler attempts to translate from low-level
  representations of computer programs into high-level
  representations. Thus it needs to model concepts from
  both the low-level machine hardware domain and from
  the high-level software programming domain.

  Understanding the classes within the source code that
  implement these models provides the quickest inroad into 
  obtaining an overall understanding of the code.

  We list all these fundamental classes here, loosely grouped
  as follows.  There is one set of classes that describe the
  \e Syntax \e Trees, which are built up from the original p-code,
  and transformed during the decompiler's simplification process.
  The \e Translation classes do the actual building of the syntax
  trees from binary executables, and the \e Transformation
  classes do the actual work of transforming the syntax trees.
  Finally there is the \e High-level classes, which for the
  decompiler represents recovered information, describing
  familiar software development concepts, like datatypes,
  prototypes, symbols, variables, etc.

  \b Syntax \b Trees
    - AddrSpace
         - A place within the reverse engineering model where data
           can be stored.  The typical address spaces are \b ram,
           modeling the main databus of a processor, and \b register,
           modeling a processor's on board registers. Data is stored a
           byte at a time at \b offsets within the AddrSpace.
         .
    - Address
         - An AddrSpace and an offset within the space forms the
           Address of the byte at that offset.
         .
    - Varnode
         - A contiguous set of bytes, given by an Address and a size,
           encoding a single value in the model.  In terms of SSA
           syntax tree, a Varnode is also a node in the tree.
         .
    - SeqNum
         - A \e sequence \e number that extends Address for distinguishing PcodeOps
           describing a single instruction.
         - \ref classseqnum
         .
    - PcodeOp
         - A single \e p-code operation. A single machine instruction is translated
           into (possibly several) operations in this Register Transfer Language.
         - \ref classpcodeop
         .
    - BlockBasic
         - A maximal sequence of p-code operations that always executes from the first PcodeOp to the last.
         - \ref classblockbasic
         .
    - Funcdata
         - The root object holding all information about a function, including:  the p-code syntax tree,
           prototype, and local symbol information.
         - \ref classfuncdata
         .
    .

  \b Translation
    - \ref classloadimage
    - \ref classtranslate

  \b Transformation
    - \ref classaction
    - \ref classrule

  \b High-level \b Representation
    - \ref classdatatype
    - \ref classtypefactory
    - \ref classhighvariable
    - \ref classfuncproto
    - \ref classcallspecs
    - \ref classsymbol
    - \ref classsymbolentry
    - \ref classscope
    - \ref classdatabase


  \section classseqnum Overview of SeqNum

  A sequence number is a form of extended address for
  multiple p-code operations that may be associated with the
  same address.  There is a normal Address field. There is a
  \b time field which is a static value, determined when an
  operation is created, that guarantees the uniqueness of
  the SeqNum. There is also an \b order field which preserves
  order information about operations within a basic block.
  This value may change if the syntax tree is manipulated.

  \code
    Address & getAddr();          // get the Address field
    uintm     getTime();          // get the time field
    uintm     getOrder();         // get the order field
  \endcode

  \section classpcodeop Overview of PcodeOp

  A single operation in the p-code language.  It has, at
  most, one Varnode output, and some number of Varnode
  inputs.  The inputs are operated on depending on the
  opcode of the instruction, producing the output.

  \code
    OpCode       code();             // get the opcode for this op
    Address &    getAddr();          // get Address of the associated processor instruction
                                     // which generated this op.
    SeqNum &     getSeqNum();        // get the full unique identifier for this op
    int4         numInput();         // get number of Varnode inputs to this op
    Varnode *    getOut();           // get Varnode output
    Varnode *    getIn(int4 i);      // get (one of the) Varnode inputs
    BlockBasic * getParent();        // get basic block containing this op
    bool         isDead();           // op may no longer be in syntax tree
    bool         isCall();           // various categories of op
    bool         isBranch();
    bool         isBoolOutput();
  \endcode

  \section classblockbasic Overview of BlockBasic

  A sequence of PcodeOps with a single path of execution.

  \code
    int4         sizeOut();         // get number of paths flowing out of this block
    int4         sizeIn();          // get number of paths flowing into this block
    BlockBasic *getIn(int4 i)       // get (one of the) blocks flowing into this
    BlockBasic *getOut(int4 i)      // get (one of the) blocks flowing out of this
    SeqNum &    getStart();         // get SeqNum of first operation in block
    SeqNum &    getStop();          // get SeqNum of last operation in block
    BlockBasic *getImmedDom();      // get immediate dominator block

    iterator    beginOp();          // get iterator to first PcodeOp in block
    iterator    endOp();
  \endcode
  
  \section classfuncdata Overview of Funcdata

  This is a container for the sytax tree associated with a
  single \e function and all other function specific data.
  It has an associated start address, function prototype,
  and local scope.

  \code
    string &       getName();            // get name of function
    Address &      getAddress();         // get Address of function's entry point
    int4           numCalls();           // number of subfunctions called by this function
    FuncCallSpecs *getCallSpecs(int4 i); // get specs for one of the subfunctions
    BlockGraph &   getBasicBlocks();     // get the collection of basic blocks

    iterator       beginLoc(Address &);                     // Search for Varnodes in tree
    iterator       beginLoc(int4,Address &);                // based on the Varnode's address
    iterator       beginLoc(int4,Address &,Address &,uintm);
    iterator       beginDef(uint4,Address &);               // Search for Varnode based on the
                                                            // address of its defining operation
  \endcode

  \section classloadimage LoadImage

  \section classaction Action

  \section classrule Rule

  \section classtranslate Translate

  Decodes machine instructions and can produce p-code.

  \code
    int4  oneInstruction(PcodeEmit &,Address &) const;   // produce pcode for one instruction
    void printAssembly(ostream &,int4,Address &) const;  // print the assembly for one instruction
  \endcode

  \section classdatatype Datatype

  Many objects have an associated Datatype, including Varnodes,
  Symbols, and FuncProtos.  A Datatype is built to resemble
  the type systems of common high-level languages like C or Java.

  \code
    type_metatype getMetatype();     // categorize type as VOID, UNKNOWN,
                                     // INT, UINT, BOOL, CODE, FLOAT,
                                     // PTR, ARRAY, STRUCT
    string &      getName();         // get name of the type
    int4          getSize();         // get number of bytes encoding this type
  \endcode

  There are base types (in varying sizes) as returned by getMetatype.

  \code
    enum type_metatype {
      TYPE_VOID,       // void type
      TYPE_UNKNOWN,    // unknown type
      TYPE_INT,        // signed integer
      TYPE_UINT,       // unsigned integer
      TYPE_BOOL,       // boolean
      TYPE_CODE,       // function data
      TYPE_FLOAT,      // floating point
    };
  \endcode

  Then these can be used to build compound types, with pointer,
  array, and structure qualifiers.
  
  \code
    class TypePointer : public Datatype  {    // pointer to (some other type)
      Datatype *getBase();                    // get Datatype being pointed to
    };
    class TypeArray : public Datatype {       // array of (some other type)
      Datatype *getBase();                    // get Datatype of array element
    };
    class TypeStruct : public Datatype {      // structure with fields of (some other types)
      TypeField *getField(int4,int4,int4 *);  // get Datatype of a field
    };
  \endcode

  \section classtypefactory TypeFactory

  This is a container for Datatypes.

  \code
    Datatype *findByName(string &);                   // find a Datatype by name
    Datatype *getTypeVoid();                          // retrieve common types
    Datatype *getTypeChar();
    Datatype *getBase(int4 size,type_metatype);
    Datatype *getTypePointer(int4,Datatype *,uint4);  // get a pointer to another type
    Datatype *getTypeArray(int4,Datatype *);          // get an array of another type
  \endcode

  \section classhighvariable HighVariable

  A single high-level variable can move in and out of
  various memory locations and registers during the course
  of its lifetime.  A HighVariable encapsulates this
  concept.  It is a collection of (low-level) Varnodes, all
  of which are used to store data for one high-level
  variable.

  \code
    int4       numInstances();      // get number of different Varnodes associated
                                    // with this variable.
    Varnode *  getInstance(int4);   // get (one of the) Varnodes associated with
                                    // this variable.
    Datatype * getType();           // get Datatype of this variable
    Symbol *   getSymbol();         // get Symbol associated with this variable
  \endcode

  \section classfuncproto FuncProto
  
  \section classcallspecs FuncCallSpecs

  \section classsymbol Symbol

  A particular symbol used for describing memory in the model.
  This behaves like a normal (high-level language) symbol.  It
  lives in a scope, has a name, and has a Datatype.

  \code
    string &      getName();          // get the name of the symbol
    Datatype *    getType();          // get the Datatype of the symbol
    Scope *       getScope();         // get the scope containing the symbol
    SymbolEntry * getFirstWholeMap(); // get the (first) SymbolEntry associated
                                      // with this symbol
  \endcode

  \section classsymbolentry SymbolEntry

  This associates a memory location with a particular symbol,
  i.e. it \e maps the symbol to memory.  Its, in theory, possible
  to have more than one SymbolEntry associated with a Symbol.

  \code
    Address &   getAddr();         // get Address of memory location
    int4        getSize();         // get size of memory location
    Symbol *    getSymbol();       // get Symbol associated with location
    RangeList & getUseLimit();     // get range of code addresses for which
                                   // this mapping applies
  \endcode

  \section classscope Scope

  This is a container for symbols.

  \code
  SymbolEntry *findAddr(Address &,Address &);           // find a Symbol by address
  SymbolEntry *findContainer(Address &,int4,Address &); // find containing symbol
  Funcdata *   findFunction(Address &);                 // find a function by entry address
  Symbol *     findByName(string &);                    // find a Symbol by name
  SymbolEntry *queryByAddr(Address &,Address &);        // search for symbols across multiple scopes
  SymbolEntry *queryContainer(Address &,int4,Address &);
  Funcdata *   queryFunction(Address &);
  Scope *      discoverScope(Address &,int4,Address &); // discover scope of an address
  string &     getName();                               // get name of scope
  Scope *      getParent();                             // get parent scope
  \endcode

  \section classdatabase Database

  This is the container for Scopes.

  \code
    Scope *getGlobalScope();                // get the root/global scope
    Scope *resolveScope(string &,Scope *);  // resolve a scope by name
  \endcode

  \section classarchitecture Architecture

  This is the repository for all information about a particular
  processor and executable. It holds the symbol table, the
  processor translator, the load image, the type database,
  and the transform engine.

  \code
  class Architecture {
    Database *     symboltab;   // the symbol table
    Translate *    translate;   // the processor translator
    LoadImage *    loader;      // the executable loadimage
    ActionDatabase allacts;     // transforms which can be performed
    TypeFactory *  types;       // the Datatype database
  };
  \endcode
 */
