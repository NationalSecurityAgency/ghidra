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

#ifndef __TYPE_HH__
#define __TYPE_HH__

#include "address.hh"

namespace ghidra {

extern AttributeId ATTRIB_ALIGNMENT;	///< Marshaling attribute "alignment"
extern AttributeId ATTRIB_ARRAYSIZE;	///< Marshaling attribute "arraysize"
extern AttributeId ATTRIB_CHAR;		///< Marshaling attribute "char"
extern AttributeId ATTRIB_CORE;		///< Marshaling attribute "core"
//extern AttributeId ATTRIB_ENUM;	///< Marshaling attribute "enum" deprecated
extern AttributeId ATTRIB_INCOMPLETE;	///< Marshaling attribute "incomplete"
//extern AttributeId ATTRIB_ENUMSIZE;	///< Marshaling attribute "enumsize" deprecated
//extern AttributeId ATTRIB_INTSIZE;	///< Marshaling attribute "intsize"  deprecated
//extern AttributeId ATTRIB_LONGSIZE;	///< Marshaling attribute "longsize" deprecated
extern AttributeId ATTRIB_OPAQUESTRING;	///< Marshaling attribute "opaquestring"
extern AttributeId ATTRIB_SIGNED;	///< Marshaling attribute "signed"
extern AttributeId ATTRIB_STRUCTALIGN;	///< Marshaling attribute "structalign"
extern AttributeId ATTRIB_UTF;		///< Marshaling attribute "utf"
extern AttributeId ATTRIB_VARLENGTH;	///< Marshaling attribute "varlength"

//extern ElementId ELEM_ABSOLUTE_MAX_ALIGNMENT;	///< Marshaling element \<absolute_max_alignment>
//extern ElementId ELEM_BITFIELD_PACKING;		///< Marshaling element \<bitfield_packing>
extern ElementId ELEM_CHAR_SIZE;		///< Marshaling element \<char_size>
//extern ElementId ELEM_CHAR_TYPE;		///< Marshaling element \<char_type>
extern ElementId ELEM_CORETYPES;		///< Marshaling element \<coretypes>
extern ElementId ELEM_DATA_ORGANIZATION;	///< Marshaling element \<data_organization>
extern ElementId ELEM_DEF;			///< Marshaling element \<def>
//extern ElementId ELEM_DEFAULT_ALIGNMENT;	///< Marshaling element \<default_alignment>
//extern ElementId ELEM_DEFAULT_POINTER_ALIGNMENT;	///< Marshaling element \<default_pointer_alignment>
//extern ElementId ELEM_DOUBLE_SIZE;		///< Marshaling element \<double_size>
extern ElementId ELEM_ENTRY;			///< Marshaling element \<entry>
extern ElementId ELEM_ENUM;			///< Marshaling element \<enum>
extern ElementId ELEM_FIELD;			///< Marshaling element \<field>
//extern ElementId ELEM_FLOAT_SIZE;		///< Marshaling element \<float_size>
extern ElementId ELEM_INTEGER_SIZE;		///< Marshaling element \<integer_size>
//extern ElementId ELEM_LONG_DOUBLE_SIZE;		///< Marshaling element \<long_double_size>
//extern ElementId ELEM_LONG_LONG_SIZE;		///< Marshaling element \<long_long_size>
extern ElementId ELEM_LONG_SIZE;		///< Marshaling element \<long_size>
//extern ElementId ELEM_MACHINE_ALIGNMENT;	///< Marshaling element \<machine_alignment>
//extern ElementId ELEM_POINTER_SHIFT;		///< Marshaling element \<pointer_shift>
extern ElementId ELEM_POINTER_SIZE;		///< Marshaling element \<pointer_size>
//extern ElementId ELEM_SHORT_SIZE;		///< Marshaling element \<short_size>
extern ElementId ELEM_SIZE_ALIGNMENT_MAP;	///< Marshaling element \<size_alignment_map>
extern ElementId ELEM_TYPE;			///< Marshaling element \<type>
//extern ElementId ELEM_TYPE_ALIGNMENT_ENABLED;	///< Marshaling element \<type_alignment_enabled>
extern ElementId ELEM_TYPEGRP;			///< Marshaling element \<typegrp>
extern ElementId ELEM_TYPEREF;			///< Marshaling element \<typeref>
//extern ElementId ELEM_USE_MS_CONVENTION;	///< Marshaling element \<use_MS_convention>
extern ElementId ELEM_WCHAR_SIZE;		///< Marshaling element \<wchar_size>
//extern ElementId ELEM_ZERO_LENGTH_BOUNDARY;	///< Marshaling element \<zero_length_boundary>

/// Print a hex dump of a data buffer to stream
extern void print_data(ostream &s,uint1 *buffer,int4 size,const Address &baseaddr);
//extern void print_char(ostream &s,int4 onechar);
//extern bool print_string(ostream &s,uint1 *buffer,int4 size);

/// The core meta-types supported by the decompiler. These are sizeless templates
/// for the elements making up the type algebra.  Index is important for Datatype::base2sub array.
enum type_metatype {
  TYPE_VOID = 17,		///< Standard "void" type, absence of type
  TYPE_SPACEBASE = 16,		///< Placeholder for symbol/type look-up calculations
  TYPE_UNKNOWN = 15,		///< An unknown low-level type. Treated as an unsigned integer.
  TYPE_INT = 14,		///< Signed integer. Signed is considered less specific than unsigned in C
  TYPE_UINT = 13,		///< Unsigned integer
  TYPE_BOOL = 12,		///< Boolean
  TYPE_CODE = 11,		///< Data is actual executable code
  TYPE_FLOAT = 10,		///< Floating-point

  TYPE_PTR = 9,			///< Pointer data-type
  TYPE_PTRREL = 8,		///< Pointer relative to another data-type (specialization of TYPE_PTR)
  TYPE_ARRAY = 7,		///< Array data-type, made up of a sequence of "element" datatype
  TYPE_ENUM_UINT = 6,		///< Unsigned enumeration data-type (specialization of TYPE_UINT)
  TYPE_ENUM_INT = 5,		///< Signed enumeration data-type (specialization of TYPE_INT)
  TYPE_STRUCT = 4,		///< Structure data-type, made up of component datatypes
  TYPE_UNION = 3,		///< An overlapping union of multiple datatypes
  TYPE_PARTIALENUM = 2,		///< Part of an enumerated value (specialization of TYPE_UINT)
  TYPE_PARTIALSTRUCT = 1,	///< Part of a structure, stored separately from the whole
  TYPE_PARTIALUNION = 0		///< Part of a union
};

/// Specializations of the core meta-types.  Each enumeration is associated with a specific #type_metatype.
/// Ordering is important: The lower the number, the more \b specific the data-type, affecting propagation.
enum sub_metatype {
  SUB_VOID = 23,		///< Compare as a TYPE_VOID
  SUB_SPACEBASE = 22,		///< Compare as a TYPE_SPACEBASE
  SUB_UNKNOWN = 21,		///< Compare as a TYPE_UNKNOWN
  SUB_PARTIALSTRUCT = 20,	///< Compare as TYPE_PARTIALSTRUCT
  SUB_INT_CHAR = 19,		///< Signed 1-byte character, sub-type of TYPE_INT
  SUB_UINT_CHAR = 18,		///< Unsigned 1-byte character, sub-type of TYPE_UINT
  SUB_INT_PLAIN = 17,		///< Compare as a plain TYPE_INT
  SUB_UINT_PLAIN = 16,		///< Compare as a plain TYPE_UINT
  SUB_INT_ENUM = 15,		///< Signed enum, sub-type of TYPE_INT
  SUB_UINT_PARTIALENUM = 14,	///< Unsigned partial enum, sub-type of TYPE_UINT
  SUB_UINT_ENUM = 13,		///< Unsigned enum, sub-type of TYPE_UINT
  SUB_INT_UNICODE = 12,		///< Signed wide character, sub-type of TYPE_INT
  SUB_UINT_UNICODE = 11,	///< Unsigned wide character, sub-type of TYPE_UINT
  SUB_BOOL = 10,		///< Compare as TYPE_BOOL
  SUB_CODE = 9,			///< Compare as TYPE_CODE
  SUB_FLOAT = 8,		///< Compare as TYPE_FLOAT
  SUB_PTRREL_UNK = 7,		///< Pointer to unknown field of struct, sub-type of TYPE_PTR
  SUB_PTR = 6,			///< Compare as TYPE_PTR
  SUB_PTRREL = 5,		///< Pointer relative to another data-type, sub-type of TYPE_PTR
  SUB_PTR_STRUCT = 4,		///< Pointer into struct, sub-type of TYPE_PTR
  SUB_ARRAY = 3,		///< Compare as TYPE_ARRAY
  SUB_STRUCT = 2,		///< Compare as TYPE_STRUCT
  SUB_UNION = 1,		///< Compare as TYPE_UNION
  SUB_PARTIALUNION = 0		///< Compare as a TYPE_PARTIALUNION
};

/// Data-type classes for the purpose of assigning storage
enum type_class {
  TYPECLASS_GENERAL = 0,	///< General purpose
  TYPECLASS_FLOAT = 1,		///< Floating-point data-types
  TYPECLASS_PTR = 2,		///< Pointer data-types
  TYPECLASS_HIDDENRET = 3,	///< Class for hidden return values
  TYPECLASS_VECTOR = 4,		///< Vector data-types
  TYPECLASS_CLASS1 = 100,	///< Architecture specific class 1
  TYPECLASS_CLASS2 = 101,	///< Architecture specific class 2
  TYPECLASS_CLASS3 = 102,	///< Architecture specific class 3
  TYPECLASS_CLASS4 = 103	///< Architecture specific class 4
};

/// Convert type \b meta-type to name
extern void metatype2string(type_metatype metatype,string &res);

/// Convert string to type \b meta-type
extern type_metatype string2metatype(const string &metastring);

/// Convert a string to a data-type class
extern type_class string2typeclass(const string &classstring);

/// Convert a data-type metatype to a data-type class
extern type_class metatype2typeclass(type_metatype meta);

class Architecture;		// Forward declarations
class PcodeOp;
class Scope;
class TypeFactory;
class TypeField;
struct DatatypeCompare;

/// \brief The base datatype class for the decompiler.
///
/// Used for symbols, function prototypes, type propagation etc.
class Datatype {
protected:
  static sub_metatype base2sub[18];
  /// Boolean properties of datatypes
  enum {
    coretype = 1,		///< This is a basic type which will never be redefined
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
    needs_resolution = 0x800,	///< Datatype (union, pointer to union) needs resolution before propagation
    force_format = 0x7000,	///< 3-bits encoding display format, 0=none, 1=hex, 2=dec, 3=oct, 4=bin, 5=char
    truncate_bigendian = 0x8000,	///< Pointer can be truncated and is big endian
    pointer_to_array = 0x10000,	///< Data-type is a pointer to an array
    warning_issued = 0x20000	///< Data-type has an associated \e warning string
  };
  friend class TypeFactory;
  friend struct DatatypeCompare;
  uint8 id;			///< A unique id for the type (or 0 if an id is not assigned)
  int4 size;			///< Size (of variable holding a value of this type)
  uint4 flags;			///< Boolean properties of the type
  string name;			///< Name of type
  string displayName;		///< Name to display in output
  type_metatype metatype;	///< Meta-type - type disregarding size
  sub_metatype submeta;		///< Sub-type of the meta-type, for comparisons
  Datatype *typedefImm;		///< The immediate data-type being typedefed by \e this
  int4 alignment;		///< Byte alignment expected for \b this data-type in addressable memory
  int4 alignSize;		///< Size of data-type rounded up to a multiple of \b alignment
  void decodeBasic(Decoder &decoder);	///< Recover basic data-type properties
  void encodeBasic(type_metatype meta,int4 align,Encoder &encoder) const;	///< Encode basic data-type properties
  void encodeTypedef(Encoder &encoder) const;	///< Encode \b this as a \e typedef element to a stream
  void markComplete(void) { flags &= ~(uint4)type_incomplete; }		///< Mark \b this data-type as completely defined
  void setDisplayFormat(uint4 format);		///< Set a specific display format
  virtual Datatype *clone(void) const=0;	///< Clone the data-type
  static uint8 hashName(const string &nm);	///< Produce a data-type id by hashing the type name
  static uint8 hashSize(uint8 id,int4 size);	///< Reversibly hash size into id
protected:
  static int4 calcAlignSize(int4 sz,int4 align);	///< Calculate aligned size, given size and alignment of data-type
public:
  /// Construct the base data-type copying low-level properties of another
  Datatype(const Datatype &op) { size = op.size; name=op.name; displayName=op.displayName; metatype=op.metatype;
    submeta=op.submeta; flags=op.flags; id=op.id; typedefImm=op.typedefImm; alignment=op.alignment; alignSize=op.alignSize; }
  /// Construct the base data-type providing size and meta-type
  Datatype(int4 s,int4 align,type_metatype m) {
    size=s; metatype=m; submeta=base2sub[m]; flags=0; id=0; typedefImm=(Datatype *)0; alignment=align; alignSize=s; }
  virtual ~Datatype(void) {}	///< Destructor
  bool isCoreType(void) const { return ((flags&coretype)!=0); }	///< Is this a core data-type
  bool isCharPrint(void) const { return ((flags&(chartype|utf16|utf32|opaque_string))!=0); }	///< Does this print as a 'char'
  bool isEnumType(void) const { return ((flags&enumtype)!=0); }		///< Is this an enumerated type
  bool isASCII(void) const { return ((flags&chartype)!=0); }	///< Does this print as an ASCII 'char'
  bool isUTF16(void) const { return ((flags&utf16)!=0); }	///< Does this print as UTF16 'wchar'
  bool isUTF32(void) const { return ((flags&utf32)!=0); }	///< Does this print as UTF32 'wchar'
  bool isVariableLength(void) const { return ((flags&variable_length)!=0); }	///< Is \b this a variable length structure
  bool hasSameVariableBase(const Datatype *ct) const;		///< Are these the same variable length data-type
  bool isOpaqueString(void) const { return ((flags&opaque_string)!=0); }	///< Is \b this an opaquely encoded string
  bool isPointerToArray(void) const { return ((flags&pointer_to_array)!=0); }	///< Is \b this a pointer to an array
  bool isPointerRel(void) const { return ((flags & is_ptrrel)!=0); }	///< Is \b this a TypePointerRel
  bool isFormalPointerRel(void) const { return (flags & (is_ptrrel | has_stripped))==is_ptrrel; }	///< Is \b this a non-ephemeral TypePointerRel
  bool hasStripped(void) const { return (flags & has_stripped)!=0; }	///< Return \b true if \b this has a stripped form
  bool isIncomplete(void) const { return (flags & type_incomplete)!=0; }	///< Is \b this an incompletely defined data-type
  bool needsResolution(void) const { return (flags & needs_resolution)!=0; }	///< Is \b this a union or a pointer to union
  bool hasWarning(void) const { return (flags & warning_issued)!=0; }	///< Has a \e warning been issued about \b this data-type
  uint4 getInheritable(void) const { return (flags & coretype); }	///< Get properties pointers inherit
  uint4 getDisplayFormat(void) const;				///< Get the display format for constants with \b this data-type
  type_metatype getMetatype(void) const { return metatype; }	///< Get the type \b meta-type
  sub_metatype getSubMeta(void) const { return submeta; }	///< Get the \b sub-metatype
  uint8 getId(void) const { return id; }			///< Get the type id
  uint8 getUnsizedId(void) const;				///< Get the type id, without variable length size adjustment
  int4 getSize(void) const { return size; }			///< Get the type size
  int4 getAlignSize(void) const { return alignSize; }		///< Get size rounded up to multiple of alignment
  int4 getAlignment(void) const { return alignment; }		///< Get the expected byte alignment
  const string &getName(void) const { return name; }		///< Get the type name
  const string &getDisplayName(void) const { return displayName; }	///< Get string to use in display
  Datatype *getTypedef(void) const { return typedefImm; }	///< Get the data-type immediately typedefed by \e this (or null)
  virtual void printRaw(ostream &s) const;			///< Print a description of the type to stream
  virtual const TypeField *findTruncation(int8 off,int4 sz,const PcodeOp *op,int4 slot,int8 &newoff) const;
  virtual Datatype *getSubType(int8 off,int8 *newoff) const; ///< Recover component data-type one-level down
  virtual Datatype *nearestArrayedComponentForward(int8 off,int8 *newoff,int8 *elSize) const;
  virtual Datatype *nearestArrayedComponentBackward(int8 off,int8 *newoff,int8 *elSize) const;

  /// \brief Get number of bytes at the given offset that are padding
  ///
  /// For the given offset into \b this data-type, determine if the byte at that offset is considered
  /// padding, and if so, return the number of bytes in the padding. Otherwise, return 0.
  /// \return the number of bytes of padding or 0
  virtual int4 getHoleSize(int4 off) const { return 0; }

  /// \brief Get the number of component sub-types making up \b this data-type
  ///
  /// \return the number of components
  virtual int4 numDepend(void) const { return 0; }

  /// \brief Get a specific component sub-type by index
  ///
  /// \param index is the index specifying which sub-type to return
  /// \return the i-th component sub-type
  virtual Datatype *getDepend(int4 index) const { return (Datatype *)0; }

  /// \brief Print (part of) the name of \b this data-type as short prefix for a label
  ///
  /// This is used for building variable names to give some indication of the variable's underlying data-type
  /// \param s is the stream write the name prefix to
  virtual void printNameBase(ostream &s) const { if (!name.empty()) s<<name[0]; }
  virtual int4 compare(const Datatype &op,int4 level) const; ///< Order types for propagation
  virtual int4 compareDependency(const Datatype &op) const; ///< Compare for storage in tree structure
  virtual void encode(Encoder &encoder) const;	///< Encode the data-type to a stream
  virtual bool isPtrsubMatching(int8 off,int8 extra,int8 multiplier) const;	///< Is this data-type suitable as input to a CPUI_PTRSUB op
  virtual Datatype *getStripped(void) const;		///< Get a stripped version of \b this for formal use in formal declarations
  virtual Datatype *resolveInFlow(PcodeOp *op,int4 slot);	///< Tailor data-type propagation based on Varnode use
  virtual Datatype* findResolve(const PcodeOp *op,int4 slot);	///< Find a previously resolved sub-type
  virtual int4 findCompatibleResolve(Datatype *ct) const;	///< Find a resolution compatible with the given data-type
  virtual const TypeField *resolveTruncation(int8 offset,PcodeOp *op,int4 slot,int8 &newoff);
  int4 typeOrder(const Datatype &op) const { if (this==&op) return 0; return compare(op,10); }	///< Order this with -op- datatype
  int4 typeOrderBool(const Datatype &op) const;	///< Order \b this with -op-, treating \e bool data-type as special
  void encodeRef(Encoder &encoder) const;	///< Encode a reference of \b this to a stream
  bool isPieceStructured(void) const;		///< Does \b this data-type consist of separate pieces?
  bool isPrimitiveWhole(void) const;		///< Is \b this made up of a single primitive
  static uint4 encodeIntegerFormat(const string &val);
  static string decodeIntegerFormat(uint4 val);
};

/// \brief A field within a structure or union
class TypeField {
public:
  int4 ident;			///< Id for identifying \b this within its containing structure or union
  int4 offset;			///< Offset (into containing structure or union) of subfield
  string name;			///< Name of subfield
  Datatype *type;		///< Data-type of subfield
  TypeField(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b this field from a stream
  TypeField(int4 id,int4 off,const string &nm,Datatype *ct) { ident=id; offset=off; name=nm; type=ct; }	///< Construct from components
  bool operator<(const TypeField &op2) const { return (offset < op2.offset); }	///< Compare based on offset
  void encode(Encoder &encoder) const;			///< Encode \b this field to a stream
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
  TypeBase(int4 s,type_metatype m) : Datatype(s,-1,m) {}
  /// Construct TypeBase from a size, meta-type, and name
  TypeBase(int4 s,type_metatype m,const string &n) : Datatype(s,-1,m) { name = n; displayName = n; }
  virtual Datatype *clone(void) const { return new TypeBase(*this); }
};

/// \brief Base type for character data-types: i.e. char
///
/// This is always presumed to be UTF-8 encoded
class TypeChar : public TypeBase {
protected:
  friend class TypeFactory;
  void decode(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b this char data-type from a stream
public:
  /// Construct TypeChar copying properties from another data-type
  TypeChar(const TypeChar &op) : TypeBase(op) { flags |= Datatype::chartype; }
  /// Construct a char (always 1-byte) given a name
  TypeChar(const string &n) : TypeBase(1,TYPE_INT,n) { flags |= Datatype::chartype; submeta = SUB_INT_CHAR; }
  virtual Datatype *clone(void) const { return new TypeChar(*this); }
  virtual void encode(Encoder &encoder) const;
};

/// \brief The unicode data-type: i.e. wchar
///
/// This supports encoding elements that are wider than 1-byte
class TypeUnicode : public TypeBase { // Unicode character type
  void setflags(void);	///< Set unicode property flags
protected:
  friend class TypeFactory;
  void decode(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b this unicode data-type from a stream
public:
  TypeUnicode(void) : TypeBase(0,TYPE_INT) {} ///< For use with decode
  TypeUnicode(const TypeUnicode &op) : TypeBase(op) {}	///< Construct from another TypeUnicode
  TypeUnicode(const string &nm,int4 sz,type_metatype m);	///< Construct given name,size, meta-type
  virtual Datatype *clone(void) const { return new TypeUnicode(*this); }
  virtual void encode(Encoder &encoder) const;
};

/// \brief Formal "void" data-type object.
///
/// A placeholder for "no data-type".
/// This should be the only object with meta-type set to TYPE_VOID
class TypeVoid : public Datatype {
protected:
  friend class TypeFactory;
  void decode(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b void data-type, with an id
public:
  /// Construct from another TypeVoid
  TypeVoid(const TypeVoid &op) : Datatype(op) { flags |= Datatype::coretype; }
  /// Constructor
  TypeVoid(void) : Datatype(0,1,TYPE_VOID) { name = "void"; displayName = name; flags |= Datatype::coretype; }
  virtual Datatype *clone(void) const { return new TypeVoid(*this); }
  virtual void encode(Encoder &encoder) const;
};

/// \brief Datatype object representing a pointer
class TypePointer : public Datatype {
protected:
  friend class TypeFactory;
  Datatype *ptrto;		///< Type being pointed to
  AddrSpace *spaceid;		///< If non-null, the address space \b this is intented to point into
  TypePointer *truncate;	///< Truncated form of the pointer (if not null)
  uint4 wordsize;               ///< What size unit does the pointer address
  static bool testForArraySlack(Datatype *dt,int8 off);	///< Test if an \e out-of-bounds offset makes sense as array slack
  void decode(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b this pointer data-type from a stream
  void calcSubmeta(void);	///< Calculate specific submeta for \b this pointer
  void calcTruncate(TypeFactory &typegrp);	// Assign a truncated pointer subcomponent if necessary
  /// Internal constructor for use with decode
  TypePointer(void) : Datatype(0,-1,TYPE_PTR) { ptrto = (Datatype *)0; wordsize=1; spaceid=(AddrSpace *)0; truncate=(TypePointer *)0; }
public:
  /// Construct from another TypePointer
  TypePointer(const TypePointer &op) : Datatype(op) { ptrto = op.ptrto; wordsize=op.wordsize; spaceid=op.spaceid; truncate=op.truncate; }
  /// Construct from a size, pointed-to type, and wordsize
  TypePointer(int4 s,Datatype *pt,uint4 ws) : Datatype(s,-1,TYPE_PTR) {
    ptrto = pt; flags = ptrto->getInheritable(); wordsize=ws; spaceid=(AddrSpace *)0; truncate=(TypePointer *)0; calcSubmeta(); }
  /// Construct from a pointed-to type and an address space attribute
  TypePointer(Datatype *pt,AddrSpace *spc) : Datatype(spc->getAddrSize(), -1, TYPE_PTR) {
    ptrto = pt; flags = ptrto->getInheritable(); spaceid=spc; wordsize=spc->getWordSize(); truncate=(TypePointer *)0; calcSubmeta(); }
  Datatype *getPtrTo(void) const { return ptrto; }	///< Get the pointed-to Datatype
  uint4 getWordSize(void) const { return wordsize; }	///< Get the size of the addressable unit being pointed to
  AddrSpace *getSpace(void) const { return spaceid; }	///< Get any address space associated with \b this pointer
  virtual void printRaw(ostream &s) const;
  virtual Datatype *getSubType(int8 off,int8 *newoff) const;
  virtual int4 numDepend(void) const { return 1; }
  virtual Datatype *getDepend(int4 index) const { return ptrto; }
  virtual void printNameBase(ostream &s) const { s << 'p'; ptrto->printNameBase(s); }
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypePointer(*this); }
  virtual void encode(Encoder &encoder) const;
  virtual TypePointer *downChain(int8 &off,TypePointer *&par,int8 &parOff,bool allowArrayWrap,TypeFactory &typegrp);
  virtual bool isPtrsubMatching(int8 off,int8 extra,int8 multiplier) const;
  virtual Datatype *resolveInFlow(PcodeOp *op,int4 slot);
  virtual Datatype* findResolve(const PcodeOp *op,int4 slot);
};

/// \brief Datatype object representing an array of elements
class TypeArray : public Datatype {
protected:
  friend class TypeFactory;
  Datatype *arrayof;		///< type of which we have an array
  int4 arraysize;		///< Number of elements in the array
  void decode(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b this array from a stream
  /// Internal constructor for decode
  TypeArray(void) : Datatype(0,-1,TYPE_ARRAY) { arraysize = 0; arrayof = (Datatype *)0; }
public:
  /// Construct from another TypeArray
  TypeArray(const TypeArray &op) : Datatype(op) { arrayof = op.arrayof; arraysize = op.arraysize; }
  /// Construct given an array size and element data-type
  TypeArray(int4 n,Datatype *ao);
  Datatype *getBase(void) const { return arrayof; }	///< Get the element data-type
  int4 numElements(void) const { return arraysize; }	///< Get the number of elements
  Datatype *getSubEntry(int4 off,int4 sz,int4 *newoff,int4 *el) const;	///< Figure out what a byte range overlaps
  virtual void printRaw(ostream &s) const;
  virtual Datatype *getSubType(int8 off,int8 *newoff) const;
  virtual int4 getHoleSize(int4 off) const;
  virtual int4 numDepend(void) const { return 1; }
  virtual Datatype *getDepend(int4 index) const { return arrayof; }
  virtual void printNameBase(ostream &s) const { s << 'a'; arrayof->printNameBase(s); }
  virtual int4 compare(const Datatype &op,int4 level) const; // For tree structure
  virtual int4 compareDependency(const Datatype &op) const; // For tree structure
  virtual Datatype *clone(void) const { return new TypeArray(*this); }
  virtual void encode(Encoder &encoder) const;
  virtual Datatype *resolveInFlow(PcodeOp *op,int4 slot);
  virtual Datatype* findResolve(const PcodeOp *op,int4 slot);
  virtual int4 findCompatibleResolve(Datatype *ct) const;
};

/// \brief An enumerated Datatype object: an integer with named values.
///
/// This supports combinations of the enumeration values (using logical OR and bit-wise complement)
/// by defining independent \b bit-fields.
class TypeEnum : public TypeBase {
public:
  /// \brief Class describing how a particular enumeration value is constructed using tokens
  class Representation {
  public:
    vector<string> matchname;	///< Name tokens that are ORed together
    bool complement;		///< If \b true, bitwise complement value after ORing
    int4 shiftAmount;		///< Number of bits to left-shift final value
    Representation(void) { complement = false; shiftAmount = 0; }	///< Constructor
  };
protected:
  friend class TypeFactory;
  map<uintb,string> namemap;	///< Map from integer to name
  void setNameMap(const map<uintb,string> &nmap) { namemap = nmap; }	///< Establish the value -> name map
  string decode(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b this enum data-type from a stream
public:
  /// Construct from another TypeEnum
  TypeEnum(const TypeEnum &op);
  /// Construct from a size and meta-type (TYPE_INT or TYPE_UINT)
  TypeEnum(int4 s,type_metatype m) : TypeBase(s,m) {
    flags |= enumtype; metatype = (m==TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT; }
  /// Construct from a size, meta-type, and name
  TypeEnum(int4 s,type_metatype m,const string &nm) : TypeBase(s,m,nm) {
    flags |= enumtype; metatype = (m==TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT; }
  map<uintb,string>::const_iterator beginEnum(void) const { return namemap.begin(); }	///< Beginning of name map
  map<uintb,string>::const_iterator endEnum(void) const { return namemap.end(); }	///< End of name map
  virtual bool hasNamedValue(uintb val) const;			///< Does \b this have a (single) name for the given value
  virtual void getMatches(uintb val,Representation &rep) const;	///< Recover the named representation
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypeEnum(*this); }
  virtual void encode(Encoder &encoder) const;
  static void assignValues(map<uintb,string> &nmap,const vector<string> &namelist,vector<uintb> &vallist,
			   const vector<bool> &assignlist,const TypeEnum *te);
};

/// \brief A composite Datatype object: A \b structure with component \b fields
class TypeStruct : public Datatype {
protected:
  friend class TypeFactory;
  vector<TypeField> field;			///< The list of fields
  void setFields(const vector<TypeField> &fd,int4 fixedSize,int4 fixedAlign);	///< Establish fields for \b this
  int4 getFieldIter(int4 off) const;		///< Get index into field list
  int4 getLowerBoundField(int4 off) const;	///< Get index of last field before or equal to given offset
  string decodeFields(Decoder &decoder,TypeFactory &typegrp);	///< Restore fields from a stream
public:
  TypeStruct(const TypeStruct &op);	///< Construct from another TypeStruct
  TypeStruct(void) : Datatype(0,-1,TYPE_STRUCT) { flags |= type_incomplete; }	///< Construct incomplete/empty TypeStruct
  vector<TypeField>::const_iterator beginField(void) const { return field.begin(); }	///< Beginning of fields
  vector<TypeField>::const_iterator endField(void) const { return field.end(); }	///< End of fields
  virtual const TypeField *findTruncation(int8 off,int4 sz,const PcodeOp *op,int4 slot,int8 &newoff) const;
  virtual Datatype *getSubType(int8 off,int8 *newoff) const;
  virtual Datatype *nearestArrayedComponentForward(int8 off,int8 *newoff,int8 *elSize) const;
  virtual Datatype *nearestArrayedComponentBackward(int8 off,int8 *newoff,int8 *elSize) const;
  virtual int4 getHoleSize(int4 off) const;
  virtual int4 numDepend(void) const { return field.size(); }
  virtual Datatype *getDepend(int4 index) const { return field[index].type; }
  virtual int4 compare(const Datatype &op,int4 level) const; // For tree structure
  virtual int4 compareDependency(const Datatype &op) const; // For tree structure
  virtual Datatype *clone(void) const { return new TypeStruct(*this); }
  virtual void encode(Encoder &encoder) const;
  virtual Datatype *resolveInFlow(PcodeOp *op,int4 slot);
  virtual Datatype* findResolve(const PcodeOp *op,int4 slot);
  virtual int4 findCompatibleResolve(Datatype *ct) const;
  static void assignFieldOffsets(vector<TypeField> &list,int4 &newSize,int4 &newAlign);	///< Assign field offsets
  static int4 scoreSingleComponent(Datatype *parent,PcodeOp *op,int4 slot);	///< Determine best type fit for given PcodeOp use
};

/// \brief A collection of overlapping Datatype objects: A \b union of component \b fields
///
/// The individual components have \b field names, as with a structure, but for a union, the components all
/// share the same memory.
class TypeUnion : public Datatype {
protected:
  friend class TypeFactory;
  vector<TypeField> field;			///< The list of fields
  void setFields(const vector<TypeField> &fd,int4 newSize,int4 newAlign);	///< Establish fields for \b this
  void decodeFields(Decoder &decoder,TypeFactory &typegrp);	///< Restore fields from a stream
public:
  TypeUnion(const TypeUnion &op);	///< Construct from another TypeUnion
  TypeUnion(void) : Datatype(0,-1,TYPE_UNION) { flags |= (type_incomplete | needs_resolution); }	///< Construct incomplete TypeUnion
  const TypeField *getField(int4 i) const { return &field[i]; }	///< Get the i-th field of the union
  virtual const TypeField *findTruncation(int8 offset,int4 sz,const PcodeOp *op,int4 slot,int8 &newoff) const;
  //  virtual Datatype *getSubType(int8 off,int8 *newoff) const;
  virtual int4 numDepend(void) const { return field.size(); }
  virtual Datatype *getDepend(int4 index) const { return field[index].type; }
  virtual int4 compare(const Datatype &op,int4 level) const; // For tree structure
  virtual int4 compareDependency(const Datatype &op) const; // For tree structure
  virtual Datatype *clone(void) const { return new TypeUnion(*this); }
  virtual void encode(Encoder &encoder) const;
  virtual Datatype *resolveInFlow(PcodeOp *op,int4 slot);
  virtual Datatype* findResolve(const PcodeOp *op,int4 slot);
  virtual int4 findCompatibleResolve(Datatype *ct) const;
  virtual const TypeField *resolveTruncation(int8 offset,PcodeOp *op,int4 slot,int8 &newoff);
  static void assignFieldOffsets(vector<TypeField> &list,int4 &newSize,int4 &newAlign,TypeUnion *tu);	///< Assign field offsets
};

/// \brief A data-type thats holds part of a TypeEnum and possible additional padding
class TypePartialEnum : public TypeEnum {
  friend class TypeFactory;
  Datatype *stripped;		///< The \e undefined data-type to use if a formal data-type is required.
  TypeEnum *parent;		///< The enumeration data-type \b this is based on
  int4 offset;			///< Byte offset with the parent enum where \b this starts
public:
  TypePartialEnum(const TypePartialEnum &op);		///< Construct from another TypePartialEnum
  TypePartialEnum(TypeEnum *par,int4 off,int4 sz,Datatype *strip);	///< Constructor
  int4 getOffset(void) const { return offset; }		///< Get the byte offset into the containing data-type
  Datatype *getParent(void) const { return parent; }	///< Get the enumeration containing \b this piece
  virtual void printRaw(ostream &s) const;
  virtual bool hasNamedValue(uintb val) const;
  virtual void getMatches(uintb val,Representation &rep) const;
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypePartialEnum(*this); }
  virtual void encode(Encoder &encoder) const;
  virtual Datatype *getStripped(void) const { return stripped; }
};

/// \brief A data-type that holds \e part of a TypeStruct or TypeArray
class TypePartialStruct : public Datatype {
  friend class TypeFactory;
  Datatype *stripped;		///< The \e undefined data-type to use if a formal data-type is required.
  Datatype *container;		///< Parent structure or array of which \b this is a part
  int4 offset;			///< Byte offset within the parent where \b this starts
public:
  TypePartialStruct(const TypePartialStruct &op);	///< Construct from another TypePartialStruct
  TypePartialStruct(Datatype *contain,int4 off,int4 sz,Datatype *strip);	///< Constructor
  int4 getOffset(void) const { return offset; }		///< Get the byte offset into the containing data-type
  Datatype *getParent(void) const { return container; }	///< Get the data-type containing \b this piece
  Datatype *getComponentForPtr(void) const;	///< Get (initial) component of array represented by \b this
  virtual void printRaw(ostream &s) const;
  virtual Datatype *getSubType(int8 off,int8 *newoff) const;
  virtual int4 getHoleSize(int4 off) const;
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypePartialStruct(*this); }
  virtual Datatype *getStripped(void) const { return stripped; }
};

/// \brief An internal data-type for holding information about a variable's relative position within a union data-type
///
/// This is a data-type that can be assigned to a Varnode offset into a Symbol, where either the Symbol itself or
/// a sub-field is a TypeUnion. In these cases, we know the Varnode is properly contained within a TypeUnion,
/// but the lack of context prevents us from deciding which field of the TypeUnion applies (and possibly
/// the sub-field of the field).
class TypePartialUnion : public Datatype {
protected:
  friend class TypeFactory;
  Datatype *stripped;		///< The \e undefined data-type to use if a formal data-type is required.
  TypeUnion *container;		///< Union data-type containing \b this partial data-type
  int4 offset;			///< Offset (in bytes) into the \e container union
public:
  TypePartialUnion(const TypePartialUnion &op);			///< Construct from another TypePartialUnion
  TypePartialUnion(TypeUnion *contain,int4 off,int4 sz,Datatype *strip);	///< Constructor
  int4 getOffset(void) const { return offset; }			///< Get the byte offset into the containing data-type
  TypeUnion *getParentUnion(void) const { return container; }	///< Get the union which \b this is part of
  virtual void printRaw(ostream &s) const;
  virtual const TypeField *findTruncation(int8 off,int4 sz,const PcodeOp *op,int4 slot,int8 &newoff) const;
  virtual int4 numDepend(void) const;
  virtual Datatype *getDepend(int4 index) const;
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypePartialUnion(*this); }
  virtual void encode(Encoder &encoder) const;
  virtual Datatype *getStripped(void) const { return stripped; }
  virtual Datatype *resolveInFlow(PcodeOp *op,int4 slot);
  virtual Datatype* findResolve(const PcodeOp *op,int4 slot);
  virtual int4 findCompatibleResolve(Datatype *ct) const;
  virtual const TypeField *resolveTruncation(int8 off,PcodeOp *op,int4 slot,int8 &newoff);
};

/// \brief Relative pointer: A pointer with a fixed offset into a specific structure or other data-type
///
/// The other data-type, the \b container, is typically a TypeStruct or TypeArray.  Even though \b this pointer
/// does not point directly to the start of the container, it is possible to access the container through \b this,
/// as the distance (the \b offset) to the start of the container is explicitly known.
class TypePointerRel : public TypePointer {
protected:
  friend class TypeFactory;
  TypePointer *stripped;	///< Same data-type with container info stripped
  Datatype *parent;		///< Parent structure or array which \b this is pointing into
  int4 offset;			///< Byte offset within the parent where \b this points to
  void markEphemeral(TypeFactory &typegrp);
  void decode(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b this relative pointer data-type from a stream
  /// Internal constructor for decode
  TypePointerRel(void) : TypePointer() { offset = 0; parent = (Datatype *)0; stripped = (TypePointer *)0; submeta = SUB_PTRREL; }
public:
  /// Construct from another TypePointerRel
  TypePointerRel(const TypePointerRel &op) : TypePointer((const TypePointer &)op) {
    offset = op.offset; parent = op.parent; stripped = op.stripped; }
  /// Construct given a size, pointed-to type, parent, and offset
  TypePointerRel(int4 sz,Datatype *pt,uint4 ws,Datatype *par,int4 off) : TypePointer(sz,pt,ws) {
    parent = par; offset = off; stripped = (TypePointer *)0; flags |= is_ptrrel; submeta = SUB_PTRREL; }
  Datatype *getParent(void) const { return parent; }	///< Get the parent data-type to which \b this pointer is offset
  bool evaluateThruParent(uintb addrOff) const;	///< Do we display given address offset as coming from the parent data-type

  /// \brief Get offset of \b this pointer relative to start of the containing data-type
  ///
  /// \return the offset value in \e address \e units
  int4 getAddressOffset(void) const { return AddrSpace::byteToAddressInt(offset, wordsize); }

  /// \brief Get offset of \b this pointer relative to start of the containing data-type
  ///
  /// \return the offset value in \e byte units
  int4 getByteOffset(void) const { return offset; }
  virtual void printRaw(ostream &s) const;
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypePointerRel(*this); }
  virtual void encode(Encoder &encoder) const;
  virtual TypePointer *downChain(int8 &off,TypePointer *&par,int8 &parOff,bool allowArrayWrap,TypeFactory &typegrp);
  virtual bool isPtrsubMatching(int8 off,int8 extra,int8 multiplier) const;
  virtual Datatype *getStripped(void) const { return stripped; }	///< Get the plain form of the pointer
  static Datatype *getPtrToFromParent(Datatype *base,int4 off,TypeFactory &typegrp);
};

class FuncProto;		// Forward declaration
class PrototypePieces;

/// \brief Datatype object representing executable code.
///
/// Sometimes, this holds the "function" being pointed to by a function pointer
class TypeCode : public Datatype {
protected:
  friend class TypeFactory;
  FuncProto *proto;		///< If non-null, this describes the prototype of the underlying function
  TypeFactory *factory;		///< Factory owning \b this
  void setPrototype(TypeFactory *tfact,const PrototypePieces &sig,Datatype *voidtype);	///< Establish a function pointer
  void setPrototype(TypeFactory *typegrp,const FuncProto *fp);	///< Set a particular function prototype on \b this
  void decodeStub(Decoder &decoder);		///< Restore stub of data-type without the full prototype
  void decodePrototype(Decoder &decoder,bool isConstructor,bool isDestructor,TypeFactory &typegrp);	///< Restore any prototype description
public:
  TypeCode(const TypeCode &op);		///< Construct from another TypeCode
  TypeCode(void);			///< Construct an incomplete TypeCode
  int4 compareBasic(const TypeCode *op) const;	///< Compare surface characteristics of two TypeCodes
  const FuncProto *getPrototype(void) const { return proto; }	///< Get the function prototype
  virtual ~TypeCode(void);
  virtual void printRaw(ostream &s) const;
  virtual Datatype *getSubType(int8 off,int8 *newoff) const;
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const;
  virtual Datatype *clone(void) const { return new TypeCode(*this); }
  virtual void encode(Encoder &encoder) const;
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
  void decode(Decoder &decoder,TypeFactory &typegrp);	///< Restore \b this spacebase data-type from a stream
public:
  /// Construct from another TypeSpacebase
  TypeSpacebase(const TypeSpacebase &op) : Datatype(op) {
    spaceid = op.spaceid; localframe=op.localframe; glb=op.glb;
  }
  /// Constructor for use with decode
  TypeSpacebase(Architecture *g) : Datatype(0,1,TYPE_SPACEBASE) { spaceid = (AddrSpace *)0; glb = g; }
  /// Construct given an address space, scope, and architecture
  TypeSpacebase(AddrSpace *id,const Address &frame,Architecture *g)
    : Datatype(0,1,TYPE_SPACEBASE), localframe(frame) { spaceid = id; glb = g; }
  Scope *getMap(void) const;	///< Get the symbol table indexed by \b this
  Address getAddress(uintb off,int4 sz,const Address &point) const;	///< Construct an Address given an offset
  virtual Datatype *getSubType(int8 off,int8 *newoff) const;
  virtual Datatype *nearestArrayedComponentForward(int8 off,int8 *newoff,int8 *elSize) const;
  virtual Datatype *nearestArrayedComponentBackward(int8 off,int8 *newoff,int8 *elSize) const;
  virtual int4 compare(const Datatype &op,int4 level) const;
  virtual int4 compareDependency(const Datatype &op) const; // For tree structure
  virtual Datatype *clone(void) const { return new TypeSpacebase(*this); }
  virtual void encode(Encoder &encoder) const;
};

/// \brief A data-type associated with a \e warning string
///
/// The warning should be presented to the user whenever the data-type is used.  A warning is typically
/// issued for ill-formed data-types that have been modified to facilitate decompiler analysis.
class DatatypeWarning {
  friend class TypeFactory;
  Datatype *dataType;		///< Data-type associated with the warning
  string warning;		///< An explanatory string which should be displayed to the user as a warning
public:
  DatatypeWarning(Datatype *dt,string warn) { dataType = dt; warning = warn; }	///< Constructor
  const string &getWarning(void) const { return warning; }	///< Get the warning string
};

/// \brief Container class for all Datatype objects in an Architecture
class TypeFactory {
  int4 sizeOfInt;		///< Size of the core "int" data-type
  int4 sizeOfLong;		///< Size of the core "long" data-type
  int4 sizeOfChar;		///< Size of the core "char" data-type
  int4 sizeOfWChar;		///< Size of the core "wchar_t" data-type
  int4 sizeOfPointer;		///< Size of pointers (into default data address space)
  int4 sizeOfAltPointer;	///< Size of alternate pointers used by architecture (if not 0)
  int4 enumsize;		///< Size of an enumerated type
  type_metatype enumtype;	///< Default enumeration meta-type (when parsing C)
  vector<int4> alignMap;	///< Alignment of primitive data-types based on their size
  DatatypeSet tree;		///< Datatypes within this factory (sorted by function)
  DatatypeNameSet nametree;	///< Cross-reference by name
  Datatype *typecache[9][8];	///< Matrix of the most common atomic data-types
  Datatype *typecache10;	///< Specially cached 10-byte float type
  Datatype *typecache16;	///< Specially cached 16-byte float type
  Datatype *type_nochar;	///< Same dimensions as char but acts and displays as an INT
  Datatype *charcache[5];	///< Cached character data-types
  list<DatatypeWarning> warnings;	///< Warnings for the user about data-types in \b this factory
  list<Datatype *> incompleteTypedef;	///< Incomplete data-types defined as a \e typedef
  Datatype *findNoName(Datatype &ct);	///< Find data-type (in this container) by function
  void insert(Datatype *newtype);	///< Insert pointer into the cross-reference sets
  Datatype *findAdd(Datatype &ct);	///< Find data-type in this container or add it
  void orderRecurse(vector<Datatype *> &deporder,DatatypeSet &mark,Datatype *ct) const;	///< Write out dependency list
  void decodeAlignmentMap(Decoder &decoder);		///< Parse a \<size_alignment_map> element
  void setDefaultAlignmentMap(void);			///< Provide default alignments for data-types
  Datatype *decodeTypedef(Decoder &decoder);		///< Restore a \<def> element describing a typedef
  Datatype *decodeEnum(Decoder &decoder,bool forcecore);	///< Restore a \<type> element describing an enumeration
  Datatype *decodeStruct(Decoder &decoder,bool forcecore);	///< Restore a \<type> element describing a structure
  Datatype *decodeUnion(Decoder &decoder,bool forcecore);	///< Restore a \<type> element describing a union
  Datatype *decodeCode(Decoder &decoder,bool isConstructor,bool isDestructor,bool forcecore);	///< Restore an element describing a code object
  Datatype *decodeTypeNoRef(Decoder &decoder,bool forcecore);	///< Restore from a stream
  void clearCache(void);		///< Clear the common type cache
  TypeChar *getTypeChar(const string &n);	///< Create a default "char" type
  TypeUnicode *getTypeUnicode(const string &nm,int4 sz,type_metatype m);	///< Create a default "unicode" type
  TypeCode *getTypeCode(const string &n);	///< Create a default "code" type
  void recalcPointerSubmeta(Datatype *base,sub_metatype sub);	///< Recalculate submeta for pointers to given base data-type
  void insertWarning(Datatype *dt,string warn);	///< Register a new data-type warning with \b this factory
  void removeWarning(Datatype *dt);		///< Remove the warning associated with the given data-type
  void resolveIncompleteTypedefs(void);		///< Redefine incomplete typedefs of data-types that are now complete
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
  int4 getAlignment(uint4 size) const;	///< Get data-type alignment based on size
  int4 getPrimitiveAlignSize(uint4 size) const;	///< Get the aligned size of a primitive data-type
  int4 getSizeOfInt(void) const { return sizeOfInt; }	///< Get the size of the default "int"
  int4 getSizeOfLong(void) const { return sizeOfLong; }	///< Get the size of the default "long"
  int4 getSizeOfChar(void) const { return sizeOfChar; }	///< Get the size of the default "char"
  int4 getSizeOfWChar(void) const { return sizeOfWChar; }	///< Get the size of the default "wchar_t"
  int4 getSizeOfPointer(void) const { return sizeOfPointer; }	///< Get the size of pointers
  int4 getSizeOfAltPointer(void) const { return sizeOfAltPointer; }	///< Get size of alternate pointers (or 0)
  Architecture *getArch(void) const { return glb; }	///< Get the Architecture object
  Datatype *findByName(const string &n);		///< Return type of given name
  Datatype *setName(Datatype *ct,const string &n); 	///< Set the given types name
  void setDisplayFormat(Datatype *ct,uint4 format);	///< Set the display format associated with the given data-type
  void setFields(const vector<TypeField> &fd,TypeStruct *ot,int4 newSize,int4 newAlign,uint4 flags);	///< Set fields on a TypeStruct
  void setFields(const vector<TypeField> &fd,TypeUnion *ot,int4 newSize,int4 newAlign,uint4 flags);	///< Set fields on a TypeUnion
  void setPrototype(const FuncProto *fp,TypeCode *newCode,uint4 flags);	///< Set the prototype on a TypeCode
  void setEnumValues(const map<uintb,string> &nmap,TypeEnum *te);	///< Set named values for an enumeration
  Datatype *decodeType(Decoder &decoder);	///< Restore Datatype from a stream
  Datatype *decodeTypeWithCodeFlags(Decoder &decoder,bool isConstructor,bool isDestructor);
  TypeVoid *getTypeVoid(void);					///< Get the "void" data-type
  Datatype *getBaseNoChar(int4 s,type_metatype m);		///< Get atomic type excluding "char"
  Datatype *getBase(int4 s,type_metatype m);			///< Get atomic type
  Datatype *getBase(int4 s,type_metatype m,const string &n);	///< Get named atomic type
  Datatype *getTypeChar(int4 s);				///< Get a character data-type by size
  TypeCode *getTypeCode(void);					///< Get an "anonymous" function data-type
  TypePointer *getTypePointerStripArray(int4 s,Datatype *pt,uint4 ws);	///< Construct a pointer data-type, stripping an ARRAY level
  TypePointer *getTypePointer(int4 s,Datatype *pt,uint4 ws);	///< Construct an absolute pointer data-type
  TypePointer *getTypePointer(int4 s,Datatype *pt,uint4 ws,const string &n);	///< Construct a named pointer data-type
  TypeArray *getTypeArray(int4 as,Datatype *ao);		///< Construct an array data-type
  TypeStruct *getTypeStruct(const string &n);			///< Create an (empty) structure
  TypePartialStruct *getTypePartialStruct(Datatype *contain,int4 off,int4 sz);	///< Create a partial structure
  TypeUnion *getTypeUnion(const string &n);			///< Create an (empty) union
  TypePartialUnion *getTypePartialUnion(TypeUnion *contain,int4 off,int4 sz);	///< Create a partial union
  TypeEnum *getTypeEnum(const string &n);			///< Create an (empty) enumeration
  TypePartialEnum *getTypePartialEnum(TypeEnum *contain,int4 off,int4 sz);	///< Create a partial enumeration
  TypeSpacebase *getTypeSpacebase(AddrSpace *id,const Address &addr);	///< Create a "spacebase" type
  TypeCode *getTypeCode(const PrototypePieces &proto);			///< Create a "function" datatype
  Datatype *getTypedef(Datatype *ct,const string &name,uint8 id,uint4 format);	///< Create a new \e typedef data-type
  TypePointerRel *getTypePointerRel(TypePointer *parentPtr,Datatype *ptrTo,int4 off);	///< Get pointer offset relative to a container
  TypePointerRel *getTypePointerRel(int4 sz,Datatype *parent,Datatype *ptrTo,int4 ws,int4 off,const string &nm);
  TypePointer *getTypePointerWithSpace(Datatype *ptrTo,AddrSpace *spc,const string &nm);
  TypePointer *resizePointer(TypePointer *ptr,int4 newSize);	///< Build a resized pointer based on the given pointer
  Datatype *getExactPiece(Datatype *ct,int4 offset,int4 size);	///< Get the data-type associated with piece of a structured data-type
  void destroyType(Datatype *ct);				///< Remove a data-type from \b this
  Datatype *concretize(Datatype *ct);				///< Convert given data-type to concrete form
  void dependentOrder(vector<Datatype *> &deporder) const;	///< Place all data-types in dependency order
  void encode(Encoder &encoder) const;			///< Encode \b this container to stream
  void encodeCoreTypes(Encoder &encoder) const;		///< Encode core types to stream
  void decode(Decoder &decoder);			///< Decode \b this from a \<typegrp> element
  void decodeCoreTypes(Decoder &decoder);		///< Initialize basic data-types from a stream
  void decodeDataOrganization(Decoder &decoder);	///< Parse a \<data_organization> element
  void parseEnumConfig(Decoder &decoder);		///< Parse the \<enum> tag
  void setCoreType(const string &name,int4 size,type_metatype meta,bool chartp);	///< Create a core data-type
  void cacheCoreTypes(void);				///< Cache common types
  list<DatatypeWarning>::const_iterator beginWarnings(void) const { return warnings.begin(); }	///< Start of data-type warnings
  list<DatatypeWarning>::const_iterator endWarnings(void) const { return warnings.end(); }	///< End of data-type warnings
#ifdef TYPEPROP_DEBUG
  static bool propagatedbg_on;		///< If \b true, display data-type propagation trace
#endif
};

/// The display format for the data-type is changed based on the given format.  A value of
/// zero clears any preexisting format.  Otherwise the value can be one of:
/// 1=\b hex, 2=\b dec, 3=\b oct, 4=\b bin, 5=\b char
/// \param format is the given format
inline void Datatype::setDisplayFormat(uint4 format)

{
  flags &= ~(uint4)force_format;	// Clear preexisting
  flags |= (format << 12);
}

/// A non-zero result indicates the type of formatting that is forced on the constant.
/// One of the following values is returned.
///   - 1 for hexadecimal
///   - 2 for decimal
///   - 3 for octal
///   - 4 for binary
///   - 5 for char
///
/// \return the forced encoding type or zero
inline uint4 Datatype::getDisplayFormat(void) const

{
  return (flags & force_format) >> 12;
}

/// If the data-type is \e variable \e length, the working id for the data-type has a contribution
/// based on the specific size of \b this instance.  This contribution is removed, and the base id is returned.
/// If the data-type is not \e variable \e length, the unaltered id is returned.
/// \return the base id of the data-type
inline uint8 Datatype::getUnsizedId(void) const

{
  if ((flags & variable_length) != 0) {
    return hashSize(id, size);
  }
  return id;
}

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

/// If a value with \b this data-type is put together from multiple pieces, is it better to display
/// this construction as a sequence of separate assignments or as a single concatenation.
/// Generally a TYPE_STRUCT or TYPE_ARRAY should be represented with separate assignments.
/// \return \b true if the data-type is put together with multiple assignments
inline bool Datatype::isPieceStructured(void) const

{
//  if (metatype == TYPE_STRUCT || metatype == TYPE_ARRAY || metatype == TYPE_UNION ||
//      metatype == TYPE_PARTIALUNION || metatype == TYPE_PARTIALSTRUCT)
  return (metatype <= TYPE_ARRAY);
}

inline TypeArray::TypeArray(int4 n,Datatype *ao) : Datatype(n*ao->getAlignSize(),ao->getAlignment(),TYPE_ARRAY)

{
  arraysize = n;
  arrayof = ao;
  // A varnode which is an array of size 1, should generally always be treated
  // as the element data-type
  if (n == 1)
    flags |= needs_resolution;
}

/// \brief Mark \b this as an ephemeral data-type, to be replaced in the final output
///
/// A \e base data-type is cached, which is a stripped version of the relative pointer, leaving
/// just a plain TypePointer object with the same underlying \b ptrto.  The base data-type
/// replaces \b this relative pointer for formal variable declarations in source code output.
/// This TypePointerRel is not considered a formal data-type but is only used to provide extra
/// context for the pointer during propagation.
/// \param typegrp is the factory from which to fetch the base pointer
inline void TypePointerRel::markEphemeral(TypeFactory &typegrp)

{
  stripped = typegrp.getTypePointer(size,ptrto,wordsize);
  flags |= has_stripped;
  // An ephemeral relative pointer that points to something unknown, propagates slightly
  // differently than a formal relative pointer
  if (ptrto->getMetatype() == TYPE_UNKNOWN)
    submeta = SUB_PTRREL_UNK;
}

} // End namespace ghidra
#endif
