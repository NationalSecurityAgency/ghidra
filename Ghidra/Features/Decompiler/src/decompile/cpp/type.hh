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
/// \file type.hh
/// \brief Classes for describing and printing data-types

#ifndef __CPUI_TYPE__
#define __CPUI_TYPE__

#include "address.hh"

/// Print a hex dump of a data buffer to stream
extern void print_data(ostream &s,uint1 *buffer,int4 size,const Address &baseaddr);
//extern void print_char(ostream &s,int4 onechar);
//extern bool print_string(ostream &s,uint1 *buffer,int4 size);

/// The core meta-types supported by the decompiler. These are sizeless templates
/// for the elements making up the type algebra.
enum type_metatype {
  TYPE_VOID = 12,		///< Standard "void" type, absence of type
  TYPE_SPACEBASE = 11,		///< Placeholder for symbol/type look-up calculations
  TYPE_UNKNOWN = 10,		///< An unknown low-level type. Treated as an unsigned integer.
  TYPE_INT = 9,			///< Signed integer. Signed is considered less specific than unsigned in C
  TYPE_UINT = 8,		///< Unsigned integer
  TYPE_BOOL = 7,		///< Boolean
  TYPE_CODE = 6,		///< Data is actual executable code
  TYPE_FLOAT = 5,		///< Floating-point

  TYPE_PTR = 4,			///< Pointer data-type
  TYPE_PTRREL = 3,		///< Pointer relative to another data-type (specialization of TYPE_PTR)
  TYPE_ARRAY = 2,		///< Array data-type, made up of a sequence of "element" datatype
  TYPE_PARTIALSTRUCT = 1,	///< Part of a structure, stored separately from the whole
  TYPE_STRUCT = 0		///< Structure data-type, made up of component datatypes
};

/// Specializations of the core meta-types.  Each enumeration is associated with a specific #type_metatype.
/// Ordering is important: The lower the number, the more \b specific the data-type, affecting propagation.
enum sub_metatype {
  SUB_VOID = 20,		///< Compare as a TYPE_VOID
  SUB_SPACEBASE = 19,		///< Compare as a TYPE_SPACEBASE
  SUB_UNKNOWN = 18,		///< Compare as a TYPE_UNKNOWN
  SUB_INT_CHAR = 17,		///< Signed 1-byte character, sub-type of TYPE_INT
  SUB_UINT_CHAR = 16,		///< Unsigned 1-byte character, sub-type of TYPE_UINT
  SUB_INT_PLAIN = 15,		///< Compare as a plain TYPE_INT
  SUB_UINT_PLAIN = 14,		///< Compare as a plain TYPE_UINT
  SUB_INT_ENUM = 13,		///< Signed enum, sub-type of TYPE_INT
  SUB_UINT_ENUM = 12,		///< Unsigned enum, sub-type of TYPE_UINT
  SUB_INT_UNICODE = 11,		///< Signed wide character, sub-type of TYPE_INT
  SUB_UINT_UNICODE = 10,		///< Unsigned wide character, sub-type of TYPE_UINT
  SUB_BOOL = 9,			///< Compare as TYPE_BOOL
  SUB_CODE = 8,			///< Compare as TYPE_CODE
  SUB_FLOAT = 7,		///< Compare as TYPE_FLOAT
  SUB_PTRREL_UNK = 6,	///< Pointer to unknown field of struct, sub-type of TYPE_PTR
  SUB_PTR = 5,			///< Compare as TYPE_PTR
  SUB_PTRREL = 4,		///< Pointer relative to another data-type, sub-type of TYPE_PTR
  SUB_PTR_STRUCT = 3,		///< Pointer into struct, sub-type of TYPE_PTR
  SUB_ARRAY = 2,		///< Compare as TYPE_ARRAY
  SUB_PARTIALSTRUCT = 1,	///< Compare as TYPE_PARTIALSTRUCT
  SUB_STRUCT = 0		///< Compare as TYPE_STRUCT
};
/// Convert type \b meta-type to name
extern void metatype2string(type_metatype metatype,string &res);

/// Convert string to type \b meta-type
extern type_metatype string2metatype(const string &metastring);

class Architecture;		// Forward declarations
class Scope;
class TypeFactory;
struct DatatypeCompare;

/// \brief The base datatype class for the decompiler.
///
/// Used for symbols, function prototypes, type propagation etc.
class Datatype {
protected:
  static sub_metatype base2sub[13];
  /// Boolean properties of datatypes
  enum {
    coretype = 1,		///< This is a basic type which will never be redefined
    // Bits above the first bit are considered a sub-metatype
    // If the metatypes are equal, we compare on sub-metatype
    // Currently this is only used to order int, char, and enum
    // The order of the sub-metatype is reversed so that
    // char comes before int1
    chartype = 2,		///< ASCII character data
    enumtype = 4,		///< An enumeration type (as well as an integer)
    poweroftwo = 8,		///< An enumeration type where all values are of 2^^n form
    utf16 = 16,			///< 16-bit wide chars in unicode UTF16
    utf32 = 32,			///< 32-bit wide chars in unicode UTF32
    opaque_string = 64,		///< Structure that should be treated as a string
    variable_length = 128,	///< May be other structures with same name different lengths
    has_stripped = 0x100,	///< Datatype has a stripped form for formal declarations
    is_ptrrel = 0x200,		///< Datatype is a TypePointerRel
    type_incomplete = 0x400,	///< Set if \b this (recursive) data-type has not been fully defined yet
  };
  friend class TypeFactory;
  friend struct DatatypeCompare;
  int4 size;			///< Size (of variable holding a value of this type)
  string name;			///< Name of type
  type_metatype metatype;	///< Meta-type - type disregarding size
  sub_metatype submeta;		///< Sub-type of of the meta-type, for comparisons
  uint4 flags;			///< Boolean properties of the type
  uint8 id;			///< A unique id for the type (or 0 if an id is not assigned)
  Datatype *typedefImm;		///< The immediate data-type being typedefed by \e this
  void restoreXmlBasic(const Element *el);	///< Recover basic data-type properties
  void saveXmlBasic(type_metatype meta,ostream &s) const;	///< Save basic data-type properties
  void saveXmlTypedef(ostream &s) const;	///< Write \b this as a \e typedef tag to stream
  void markComplete(void) { flags &= ~(uint4)type_incomplete; }		///< Mark \b this data-type as completely defined
  virtual Datatype *clone(void) const=0;	///< Clone the data-type
  static uint8 hashName(const string &nm);	///< Produce a data-type id by hashing the type name
  static uint8 hashSize(uint8 id,int4 size);	///< Reversibly hash size into id
public:
  /// Construct the base data-type copying low-level properties of another
  Datatype(const Datatype &op) { size = op.size; name=op.name; metatype=op.metatype; submeta=op.submeta; flags=op.flags;
    id=op.id; typedefImm=op.typedefImm; }
  /// Construct the base data-type providing size and meta-type
  Datatype(int4 s,type_metatype m) { size=s; metatype=m; submeta=base2sub[m]; flags=0; id=0; typedefImm=(Datatype *)0; }
  virtual ~Datatype(void) {}	///< Destructor
  bool isCoreType(void) const { return ((flags&coretype)!=0); }	///< Is this a core data-type
  bool isCharPrint(void) const { return ((flags&(chartype|utf16|utf32|opaque_string))!=0); }	///< Does this print as a 'char'
  bool isEnumType(void) const { return ((flags&enumtype)!=0); }		///< Is this an enumerated type
  bool isPowerOfTwo(void) const { return ((flags&poweroftwo)!=0); }	///< Is this a flag-based enumeration
  bool isASCII(void) const { return ((flags&chartype)!=0); }	///< Does this print as an ASCII 'char'
  bool isUTF16(void) const { return ((flags&utf16)!=0); }	///< Does this print as UTF16 'wchar'
  bool isUTF32(void) const { return ((flags&utf32)!=0); }	///< Does this print as UTF32 'wchar'
  bool isVariableLength(void) const { return ((flags&variable_length)!=0); }	///< Is \b this a variable length structure
  bool hasSameVariableBase(const Datatype *ct) const;		///< Are these the same variable length data-type
  bool isOpaqueString(void) const { return ((flags&opaque_string)!=0); }	///< Is \b this an opaquely encoded string
  bool isPointerRel(void) const { return ((flags & is_ptrrel)!=0); }	///< Is \b this a TypePointerRel
  bool isFormalPointerRel(void) const { return (flags & (is_ptrrel | has_stripped))==is_ptrrel; }	///< Is \b this a non-ephemeral TypePointerRel
  bool hasStripped(void) const { return (flags & has_stripped)!=0; }	///< Return \b true if \b this has a stripped form
  bool isIncomplete(void) const { return (flags & type_incomplete)!=0; }	///< Is \b this an incompletely defined data-type
  uint4 getInheritable(void) const { return (flags & coretype); }	///< Get properties pointers inherit
  type_metatype getMetatype(void) const { return metatype; }	///< Get the type \b meta-type
  sub_metatype getSubMeta(void) const { return submeta; }	///< Get the \b sub-metatype
  uint8 getId(void) const { return id; }			///< Get the type id
  int4 getSize(void) const { return size; }			///< Get the type size
  const string &getName(void) const { return name; }		///< Get the type name
  Datatype *getTypedef(void) const { return typedefImm; }	///< Get the data-type immediately typedefed by \e this (or null)
  virtual void printRaw(ostream &s) const;			///< Print a description of the type to stream
  virtual Datatype *getSubType(uintb off,uintb *newoff) const; ///< Recover component data-type one-level down
  virtual Datatype *nearestArrayedComponentForward(uintb off,uintb *newoff,int4 *elSize) const;
  virtual Datatype *nearestArrayedComponentBackward(uintb off,uintb *newoff,int4 *elSize) const;
  virtual int4 numDepend(void) const { return 0; }	///< Return number of component sub-types
  virtual Datatype *getDepend(int4 index) const { return (Datatype *)0; }	///< Return the i-th component sub-type
  virtual void printNameBase(ostream &s) const { if (!name.empty()) s<<name[0]; } ///< Print name as short prefix
  virtual int4 compare(const Datatype &op,int4 level) const; ///< Order types for propagation
  virtual int4 compareDependency(const Datatype &op) const; ///< Compare for storage in tree structure
  virtual void saveXml(ostream &s) const;	///< Serialize the data-type to XML
  virtual bool isPtrsubMatching(uintb off) const;	///< Is this data-type suitable as input to a CPUI_PTRSUB op
  virtual Datatype *getStripped(void) const;		///< Get a stripped version of \b this for formal use in formal declarations
  int4 typeOrder(const Datatype &op) const { if (this==&op) return 0; return compare(op,10); }	///< Order this with -op- datatype
  int4 typeOrderBool(const Datatype &op) const;	///< Order \b this with -op-, treating \e bool data-type as special
  void saveXmlRef(ostream &s) const;	///< Write an XML reference of \b this to stream
};

/// \brief Specifies subfields of a structure or what a pointer points to
struct TypeField {
  int4 offset;			///< Offset (into containing struct) of subfield
  string name;			///< Name of subfield
  Datatype *type;		///< type of subfield
  bool operator<(const TypeField &op2) const { return (offset < op2.offset); }	///< Compare based on offset
};

/// Compare two Datatype pointers for equivalence of their description
struct DatatypeCompare {
  /// Comparison operator
  bool operator()(const Datatype *a,const Datatype *b) const {
    int4 res = a->compareDependency(*b);
    if (res != 0) return (res<0);
    return a->getId() < b->getId(); }
};

/// Compare two Datatype pointers: first by name, then by id
struct DatatypeNameCompare {
  /// Comparison operator
  bool operator()(const Datatype *a,const Datatype *b) const {
    int4 res = a->getName().compare( b->getName() );
    if (res != 0) return (res < 0);
    return a->getId() < b->getId(); }
};

/// A set of data-types sorted by function
typedef set<Datatype *,DatatypeCompare> DatatypeSet;

/// A set of data-types sorted by name
typedef set<Datatype *,DatatypeNameCompare> DatatypeNameSet;

/// \brief Base class for the fundamental atomic types.
///
/// Data-types with a name, size, and meta-type
class TypeBase : public Datatype {
protected:
  friend class TypeFactory;
public:
  /// Construct TypeBase copying properties from another data-type
  TypeBase(const TypeBase &op) : Datatype(op) {}
  /// Construct TypeBase from a size and meta-type
  TypeBase(int4 s,type_metatype m) : Datatype(s,m) {}
  /// Construct TypeBase from a size, meta-type, and name
  TypeBase(int4 s,type_metatype m,const string &n) : Datatype(s,m) { name = n; }
  virtual Datatype *clone(void) const { return new TypeBase(*this); }
};

/// \brief Base type for character data-types: i.e. char
///
/// This is always presumed to be UTF-8 encoded
class TypeChar : public TypeBase {
protected:
  friend class TypeFactory;
  void restoreXml(const Element *el,TypeFactory &typegrp);	///< Restore \b this char data-type from an XML element
public:
  /// Construct TypeChar copying properties from another data-type
  TypeChar(const TypeChar &op) : TypeBase(op) { flags |= Datatype::chartype; }
  /// Construct a char (always 1-byte) given a name
  TypeChar(const string &n) : TypeBase(1,TYPE_INT,n) { flags |= Datatype::chartype; submeta = SUB_INT_CHAR; }
  virtual Datatype *clone(void) const { return new TypeChar(*this); }
  virtual void saveXml(ostream &s) const;
};

/// \brief The unicode data-type: i.e. wchar
///
/// This supports encoding elements that are wider than 1-byte
class TypeUnicode : public TypeBase { // Unicode character type
  void setflags(void);	///< Set unicode property flags
protected:
  friend class TypeFactory;
  void restoreXml(const Element *el,TypeFactory &typegrp);	///< Restore \b this unicode data-type from an XML element
public:
  TypeUnicode(void) : TypeBase(0,TYPE_INT) {} ///< For use with restoreXml
  TypeUnicode(const TypeUnicode &op) : TypeBase(op) {}	///< Construct from another TypeUnicode
  TypeUnicode(const string &nm,int4 sz,type_metatype m);	///< Construct given name,size, meta-type
  virtual Datatype *clone(void) const { return new TypeUnicode(*this); }
  virtual void saveXml(ostream &s) const;
};

/// \brief Formal "void" data-type object.
///
/// A placeholder for "no data-type".
/// This should be the only object with meta-type set to TYPE_VOID
class TypeVoid : public Datatype {
protected:
  friend class TypeFactory;
public:
  /// Construct from another TypeVoid
  TypeVoid(const TypeVoid &op) : Datatype(op) { flags |= Datatype::coretype; }
  /// Constructor
  TypeVoid(void) : Datatype(0,TYPE_VOID) { name = "void"; flags |= Datatype::coretype; }
  virtual Datatype *clone(void) const { return new TypeVoid(*this); }
  virtual void saveXml(ostream &s) const;
};

/// \brief Datatype object representing a pointer
class TypePointer : public Datatype {
protected:
  friend class TypeFactory;
  Datatype *ptrto;		///< Type being pointed to
  uint4 wordsize;               ///< What size unit does the pointer address
  void restoreXml(const Element *el,TypeFactory &typegrp);	///< Restore \b this pointer data-type from an XML element
  void calcSubmeta(void);	///< Calculate specific submeta for \b this pointer
  /// Internal constructor for use with restoreXml
  TypePointer(void) : Datatype(0,TYPE_PTR) { ptrto = (Datatype *)0; wordsize=1; }
public:
  /// Construct from another TypePointer
  TypePointer(const TypePointer &op) : Datatype(op) { ptrto = op.ptrto; wordsize=op.wordsize; }
  /// Construct from a size, pointed-to type, and wordsize
  TypePointer(int4 s,Datatype *pt,uint4 ws) : Datatype(s,TYPE_PTR) {
    ptrto = pt; flags = ptrto->getInheritable(); wordsize=ws; calcSubmeta(); }
  Datatype *getPtrTo(void) const { return ptrto; }	///< Get the pointed-to Datatype
  uint4 getWordSize(void) const { return wordsize; }	///< Get the wordsize of the pointer
  virtual void printRaw(ostream &s) const;
  virtual int4 numDepend(void) const { return 1; }
  virtual Datatype *getDepend(int4 index) const { return ptrto; }
  virtual void printNameBase(ostream &s) const { s << 'p'; ptrto->printNameBase(s); }
  virtual int4 compare(const Datatype &op,int4 level) const; // For tree structure
  virtual int4 compareDependency(const Datatype &op) const; // For tree structure
  virtual Datatype *clone(void) const { return new TypePointer(*this); }
  virtual void saveXml(ostream &s) const;
  virtual TypePointer *downChain(uintb &off,TypePointer *&par,uintb &parOff,bool allowArrayWrap,TypeFactory &typegrp);
  virtual bool isPtrsubMatching(uintb off) const;
};

/// \brief Datatype object representing an array of elements
class TypeArray : public Datatype {
protected:
  friend class TypeFactory;
  Datatype *arrayof;		///< type of which we have an array
  int4 arraysize;		///< Number of elements in the array
  void restoreXml(const Element *el,TypeFactory &typegrp);	///< Restore \b this array from an XML element
  /// Internal constructor for restoreXml
  TypeArray(void) : Datatype(0,TYPE_ARRAY) { arraysize = 0; arrayof = (Datatype *)0; }
public:
  /// Construct from another TypeArray
  TypeArray(const TypeArray &op) : Datatype(op) { arrayof = op.arrayof; arraysize = op.arraysize; }
  /// Construct given an array size and element data-type
  TypeArray(int4 n,Datatype *ao) : Datatype(n*ao->getSize(),TYPE_ARRAY) {
    arraysize = n; arrayof = ao; }
  Datatype *getBase(void) const { return arrayof; }	///< Get the element data-type
  int4 numElements(void) const { return arraysize; }	///< Get the number of elements
  Datatype *getSubEntry(int4 off,int4 sz,int4 *newoff,int4 *el) const;	///< Figure out what a byte range overlaps
  virtual void printRaw(ostream &s) const;
  virtual Datatype *getSubType(uintb off,uintb *newoff) const;
  virtual int4 numDepend(void) const { return 1; }
  virtual Datatype *getDepend(int4 index) const { return arrayof; }
  virtual void printNameBase(ostream &s) const { s << 'a'; arrayof->printNameBase(s); }
  virtual int4 compare(const Datatype &op,int4 level) const; // For tree structure
  virtual int4 compareDependency(const Datatype &op) const; // For tree structure
  virtual Datatype *clone(void) const { return new TypeArray(*this); }
  virtual void saveXml(ostream &s) const;
};

/// \brief An enumerated Datatype object: an integer with named values.
///
/// This supports combinations of the enumeration values (using logical OR and bit-wise complement)
/// by defining independent \b bit-fields.
class TypeEnum : public TypeBase {
protected:
  friend class TypeFactory;
  map<uintb,string> namemap;	///< Map from integer to name
  vector<uintb> masklist;	///< Masks for each bitfield within the enum
  void setNameMap(const map<uintb,string> &nmap);	///< Establish the value -> name map
  void restoreXml(const Element *el,TypeFactory &typegrp);	///< Restore \b this enum data-type from an XML element
public:
  /// Construct from another TypeEnum
  TypeEnum(const TypeEnum &op);
  /// Construct from a size and meta-type (TYPE_INT or TYPE_UINT)
  TypeEnum(int4 s,type_metatype m) : TypeBase(s,m) {
    flags |= enumtype; submeta = (m==TYPE_INT) ? SUB_INT_ENUM : SUB_UINT_ENUM; }
  /// Construct from a size, meta-type, and name
  TypeEnum(int4 s,type_metatype m,const string &nm) : TypeBase(s,m,nm) {
    flags |= enumtype; submeta = (m==TYPE_INT) ? SUB_INT_ENUM : SUB_UINT_ENUM; }
  map<uintb,string>::const_iterator beginEnum(void) const { return namemap.begin(); }	///< Beginning of name map
  map<uintb,string>::const_iterator endEnum(void) const { return namemap.end(); }	///< End of name map
  bool getMatches(uintb val,vector<string> &matchname) const;	///< Recover the named representation
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypeEnum(*this); }
  virtual void saveXml(ostream &s) const;
};

/// \brief A composite Datatype object: A "structure" with component "fields"
class TypeStruct : public Datatype {
protected:
  friend class TypeFactory;
  vector<TypeField> field;			///< The list of fields
  void setFields(const vector<TypeField> &fd);	///< Establish fields for \b this
  int4 getFieldIter(int4 off) const;		///< Get index into field list
  int4 getLowerBoundField(int4 off) const;	///< Get index of last field before or equal to given offset
  void restoreFields(const Element *el,TypeFactory &typegrp);	///< Restore fields from XML description
public:
  TypeStruct(const TypeStruct &op);	///< Construct from another TypeStruct
  TypeStruct(void) : Datatype(0,TYPE_STRUCT) { flags |= type_incomplete; }	///< Construct incomplete/empty TypeStruct
  vector<TypeField>::const_iterator beginField(void) const { return field.begin(); }	///< Beginning of fields
  vector<TypeField>::const_iterator endField(void) const { return field.end(); }	///< End of fields
  const TypeField *getField(int4 off,int4 sz,int4 *newoff) const;	///< Get field based on offset
  virtual Datatype *getSubType(uintb off,uintb *newoff) const;
  virtual Datatype *nearestArrayedComponentForward(uintb off,uintb *newoff,int4 *elSize) const;
  virtual Datatype *nearestArrayedComponentBackward(uintb off,uintb *newoff,int4 *elSize) const;
  virtual int4 numDepend(void) const { return field.size(); }
  virtual Datatype *getDepend(int4 index) const { return field[index].type; }
  virtual int4 compare(const Datatype &op,int4 level) const; // For tree structure
  virtual int4 compareDependency(const Datatype &op) const; // For tree structure
  virtual Datatype *clone(void) const { return new TypeStruct(*this); }
  virtual void saveXml(ostream &s) const;
};

/// \brief A pointer data-type that knows it is offset relative to another data-type
///
/// The other data, the \b container, is typically a TypeStruct or TypeArray.  Even though \b this pointer
/// does not point directly to the start of the container, it is possible to access the container through \b this,
/// as the distance (the \b offset) to the start of the container is explicitly known.
class TypePointerRel : public TypePointer {
protected:
  friend class TypeFactory;
  TypePointer *stripped;	///< Same data-type with container info stripped
  Datatype *parent;		///< Parent structure or array which \b this is pointing into
  int4 offset;			///< Byte offset within the parent where \b this points to
  void cacheStrippedType(TypeFactory &typegrp);
  void restoreXml(const Element *el,TypeFactory &typegrp);	///< Restore \b this relative pointer data-type from an XML element
  /// Internal constructor for restoreXml
  TypePointerRel(void) : TypePointer() { offset = 0; parent = (Datatype *)0; stripped = (TypePointer *)0; submeta = SUB_PTRREL; }
public:
  /// Construct from another TypePointerRel
  TypePointerRel(const TypePointerRel &op) : TypePointer((const TypePointer &)op) {
    offset = op.offset; parent = op.parent; stripped = op.stripped; }
  /// Construct given a size, pointed-to type, parent, and offset
  TypePointerRel(int4 sz,Datatype *pt,uint4 ws,Datatype *par,int4 off) : TypePointer(sz,pt,ws) {
    parent = par; offset = off; stripped = (TypePointer *)0; flags |= is_ptrrel;
    submeta = pt->getMetatype()==TYPE_UNKNOWN ? SUB_PTRREL_UNK : SUB_PTRREL; }
  Datatype *getParent(void) const { return parent; }	///< Get the parent data-type to which \b this pointer is offset
  bool evaluateThruParent(uintb addrOff) const;	///< Do we display given address offset as coming from the parent data-type

  /// \brief Get offset of \b this pointer relative to start of the containing data-type
  ///
  /// \return the offset value in \e address \e units
  int4 getPointerOffset(void) const { return AddrSpace::byteToAddressInt(offset, wordsize); }
  virtual void printRaw(ostream &s) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypePointerRel(*this); }
  virtual void saveXml(ostream &s) const;
  virtual TypePointer *downChain(uintb &off,TypePointer *&par,uintb &parOff,bool allowArrayWrap,TypeFactory &typegrp);
  virtual bool isPtrsubMatching(uintb off) const;
  virtual Datatype *getStripped(void) const { return stripped; }	///< Get the plain form of the pointer
  static Datatype *getPtrToFromParent(Datatype *base,int4 off,TypeFactory &typegrp);
};

class FuncProto;		// Forward declaration
class ProtoModel;

/// \brief Datatype object representing executable code.
///
/// Sometimes, this holds the "function" being pointed to by a function pointer
class TypeCode : public Datatype {
protected:
  friend class TypeFactory;
  FuncProto *proto;		///< If non-null, this describes the prototype of the underlying function
  TypeFactory *factory;		///< Factory owning \b this
  void setPrototype(TypeFactory *tfact,ProtoModel *model,
		    Datatype *outtype,const vector<Datatype *> &intypes,
		    bool dotdotdot,Datatype *voidtype);	///< Establish a function pointer
  void setPrototype(TypeFactory *typegrp,const FuncProto *fp);	///< Set a particular function prototype on \b this
  void restoreStub(const Element *el);		///< Restore stub of data-type without the full prototype
  void restorePrototype(const Element *el,bool isConstructor,bool isDestructor,TypeFactory &typegrp);	///< Restore any prototype description
public:
  TypeCode(const TypeCode &op);		///< Construct from another TypeCode
  TypeCode(void);			///< Construct an incomplete TypeCode
  int4 compareBasic(const TypeCode *op) const;	///< Compare surface characteristics of two TypeCodes
  const FuncProto *getPrototype(void) const { return proto; }	///< Get the function prototype
  virtual ~TypeCode(void);
  virtual void printRaw(ostream &s) const;
  virtual Datatype *getSubType(uintb off,uintb *newoff) const;
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypeCode(*this); }
  virtual void saveXml(ostream &s) const;
};

/// \brief Special Datatype object used to describe pointers that index into the symbol table
///
/// A TypeSpacebase treats a specific AddrSpace as "structure" that will get indexed in to.
/// This facilitates type propagation from local symbols into the stack space and
/// from global symbols into the RAM space.
class TypeSpacebase : public Datatype {
  friend class TypeFactory;
  AddrSpace *spaceid;		///< The address space we are treating as a structure
  Address localframe;		///< Address of function whose symbol table is indexed (or INVALID for "global")
  Architecture *glb;		///< Architecture for accessing symbol table
  void restoreXml(const Element *el,TypeFactory &typegrp);	///< Restore \b this spacebase data-type from an XML element
public:
  /// Construct from another TypeSpacebase
  TypeSpacebase(const TypeSpacebase &op) : Datatype(op) {
    spaceid = op.spaceid; localframe=op.localframe; glb=op.glb;
  }
  /// Construct given an address space, scope, and architecture
  TypeSpacebase(AddrSpace *id,const Address &frame,Architecture *g)
    : Datatype(0,TYPE_SPACEBASE), localframe(frame) { spaceid = id; glb = g; }
  Scope *getMap(void) const;	///< Get the symbol table indexed by \b this
  Address getAddress(uintb off,int4 sz,const Address &point) const;	///< Construct an Address given an offset
  virtual Datatype *getSubType(uintb off,uintb *newoff) const;
  virtual Datatype *nearestArrayedComponentForward(uintb off,uintb *newoff,int4 *elSize) const;
  virtual Datatype *nearestArrayedComponentBackward(uintb off,uintb *newoff,int4 *elSize) const;
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const; // For tree structure
  virtual Datatype *clone(void) const { return new TypeSpacebase(*this); }
  virtual void saveXml(ostream &s) const;
};

/// \brief Container class for all Datatype objects in an Architecture
class TypeFactory {
  int4 sizeOfInt;		///< Size of the core "int" datatype
  int4 align;			///< Alignment of structures
  int4 enumsize;		///< Size of an enumerated type
  type_metatype enumtype;	///< Default enumeration meta-type (when parsing C)
  DatatypeSet tree;		///< Datatypes within this factory (sorted by function)
  DatatypeNameSet nametree;	///< Cross-reference by name
  Datatype *typecache[9][8];	///< Matrix of the most common atomic data-types
  Datatype *typecache10;	///< Specially cached 10-byte float type
  Datatype *typecache16;	///< Specially cached 16-byte float type
  Datatype *type_nochar;	///< Same dimensions as char but acts and displays as an INT
  Datatype *findNoName(Datatype &ct);	///< Find data-type (in this container) by function
  void insert(Datatype *newtype);	///< Insert pointer into the cross-reference sets
  Datatype *findAdd(Datatype &ct);	///< Find data-type in this container or add it
  void orderRecurse(vector<Datatype *> &deporder,DatatypeSet &mark,Datatype *ct) const;	///< Write out dependency list
  Datatype *restoreTypedef(const Element *el);		///< Restore a \<def> XML tag describing a typedef
  Datatype *restoreStruct(const Element *el,bool forcecore);	///< Restore a \<type> XML tag describing a structure
  Datatype *restoreCode(const Element *el,bool isConstructor,bool isDestructor,bool forcecore);	///< Restore XML tag describing a code object
  Datatype *restoreXmlTypeNoRef(const Element *el,bool forcecore);	///< Restore from an XML tag
  void clearCache(void);		///< Clear the common type cache
  TypeChar *getTypeChar(const string &n);	///< Create a default "char" type
  TypeUnicode *getTypeUnicode(const string &nm,int4 sz,type_metatype m);	///< Create a default "unicode" type
  TypeCode *getTypeCode(const string &n);	///< Create a default "code" type
  void recalcPointerSubmeta(Datatype *base,sub_metatype sub);	///< Recalculate submeta for pointers to given base data-type
protected:
  Architecture *glb;		///< The Architecture object that owns this TypeFactory
  Datatype *findByIdLocal(const string &nm,uint8 id) const;	///< Search locally by name and id
  virtual Datatype *findById(const string &n,uint8 id,int4 sz);		///< Search by \e name and/or \e id
public:
  TypeFactory(Architecture *g);	///< Construct a factory
  void setupSizes(void);	///< Derive some size information from Architecture
  void clear(void);		///< Clear out all types
  void clearNoncore(void);	///< Clear out non-core types
  virtual ~TypeFactory(void);	///< Destructor
  void setStructAlign(int4 al) { align = al; }		///< Set the default structure alignment
  int4 getStructAlign(void) const { return align; }	///< Get the default structure alignment
  int4 getSizeOfInt(void) const { return sizeOfInt; }	///< Get the size of the default "int"
  Architecture *getArch(void) const { return glb; }	///< Get the Architecture object
  Datatype *findByName(const string &n);		///< Return type of given name
  Datatype *setName(Datatype *ct,const string &n); 	///< Set the given types name
  bool setFields(vector<TypeField> &fd,TypeStruct *ot,int4 fixedsize,uint4 flags);	///< Set fields on a TypeStruct
  void setPrototype(const FuncProto *fp,TypeCode *newCode,uint4 flags);	///< Set the prototype on a TypeCode
  bool setEnumValues(const vector<string> &namelist,
		      const vector<uintb> &vallist,
		      const vector<bool> &assignlist,
		      TypeEnum *te);		///< Set named values for an enumeration
  Datatype *restoreXmlType(const Element *el);	///< Restore Datatype from XML
  Datatype *restoreXmlTypeWithCodeFlags(const Element *el,bool isConstructor,bool isDestructor);
  TypeVoid *getTypeVoid(void);					///< Get the "void" data-type
  Datatype *getBaseNoChar(int4 s,type_metatype m);		///< Get atomic type excluding "char"
  Datatype *getBase(int4 s,type_metatype m);			///< Get atomic type
  Datatype *getBase(int4 s,type_metatype m,const string &n);	///< Get named atomic type
  TypeCode *getTypeCode(void);					///< Get an "anonymous" function data-type
  TypePointer *getTypePointerStripArray(int4 s,Datatype *pt,uint4 ws);	///< Construct a pointer data-type, stripping an ARRAY level
  TypePointer *getTypePointer(int4 s,Datatype *pt,uint4 ws);	///< Construct an absolute pointer data-type
  TypePointer *getTypePointer(int4 s,Datatype *pt,uint4 ws,const string &n);	///< Construct a named pointer data-type
  TypePointer *getTypePointerNoDepth(int4 s,Datatype *pt,uint4 ws);	///< Construct a depth limited pointer data-type
  TypeArray *getTypeArray(int4 as,Datatype *ao);		///< Construct an array data-type
  TypeStruct *getTypeStruct(const string &n);			///< Create an (empty) structure
  TypeEnum *getTypeEnum(const string &n);			///< Create an (empty) enumeration
  TypeSpacebase *getTypeSpacebase(AddrSpace *id,const Address &addr);	///< Create a "spacebase" type
  TypeCode *getTypeCode(ProtoModel *model,Datatype *outtype,
			const vector<Datatype *> &intypes,
			bool dotdotdot);			///< Create a "function" datatype
  Datatype *getTypedef(Datatype *ct,const string &name,uint8 id);	///< Create a new \e typedef data-type
  TypePointerRel *getTypePointerRel(TypePointer *parentPtr,Datatype *ptrTo,int4 off);	///< Get pointer offset relative to a container
  TypePointerRel *getTypePointerRel(int4 sz,Datatype *parent,Datatype *ptrTo,int4 ws,int4 off,const string &nm);
  void destroyType(Datatype *ct);				///< Remove a data-type from \b this
  Datatype *concretize(Datatype *ct);				///< Convert given data-type to concrete form
  void dependentOrder(vector<Datatype *> &deporder) const;	///< Place all data-types in dependency order
  void saveXml(ostream &s) const;			///< Save \b this container to stream
  void saveXmlCoreTypes(ostream &s) const;		///< Save core types to stream
  void restoreXml(const Element *el);			///< Restore \b this container from a stream
  void restoreXmlCoreTypes(const Element *el);		///< Initialize basic type names
  void parseDataOrganization(const Element *el);	///< Parse the \<data_organization> tag
  void parseEnumConfig(const Element *el);		///< Parse the \<enum> tag
  void setCoreType(const string &name,int4 size,type_metatype meta,bool chartp);	///< Create a core data-type
  void cacheCoreTypes(void);				///< Cache common types
};

/// Order data-types, with special handling of the \e bool data-type. Data-types are compared
/// using the normal ordering, but \e bool is ordered after all other data-types. A return value
/// of 0 indicates the data-types are the same, -1 indicates that \b this is prefered (ordered earlier),
/// and 1 indicates \b this is ordered later.
/// \param op is the other data-type to compare with \b this
/// \return -1, 0, or 1
inline int4 Datatype::typeOrderBool(const Datatype &op) const

{
  if (this == &op) return 0;
  if (metatype == TYPE_BOOL) return 1;		// Never prefer bool over other data-types
  if (op.metatype == TYPE_BOOL) return -1;
  return compare(op,10);
}

/// \brief Set up the base pointer data-type \b this is modeling
///
/// This base data-type is used for formal variable declarations in source code output.
/// Calling this method marks the TypePointerRel as an ephemeral data-type.  The TypePointerRel
/// is not considered a formal data-type and is replaced with the base pointer data-type, after propagation,
/// in the final decompiler output.
/// \param typegrp is the factory from which to fetch the base pointer
inline void TypePointerRel::cacheStrippedType(TypeFactory &typegrp)

{
  stripped = typegrp.getTypePointer(size,ptrto,wordsize);
  flags |= has_stripped;
}

#endif
