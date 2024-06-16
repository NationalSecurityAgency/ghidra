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
/// \file cpool.hh
/// \brief Definitions to support a constant pool for \e deferred compilation languages (i.e. java byte-code)

#ifndef __CPOOL_HH__
#define __CPOOL_HH__

#include "type.hh"

namespace ghidra {

extern AttributeId ATTRIB_A;		///< Marshaling attribute "a"
extern AttributeId ATTRIB_B;		///< Marshaling attribute "b"
extern AttributeId ATTRIB_LENGTH;	///< Marshaling attribute "length"
extern AttributeId ATTRIB_TAG;		///< Marshaling attribute "tag"

extern ElementId ELEM_CONSTANTPOOL;	///< Marshaling element \<constantpool>
extern ElementId ELEM_CPOOLREC;		///< Marshaling element \<cpoolrec>
extern ElementId ELEM_REF;		///< Marshaling element \<ref>
extern ElementId ELEM_TOKEN;		///< Marshaling element \<token>

/// \brief A description of a byte-code object referenced by a constant
///
/// Byte-code languages can make use of objects that the \e system knows about
/// but which aren't fully embedded in the encoding of instructions that use them.
/// Instead the instruction refers to the object via a special encoded reference. This class
/// describes one object described by such a reference. In order to provide a concrete
/// interpretation of the instruction (i.e. a p-code translation), these objects generally
/// resolve to some sort of constant value (hence the term \b constant \b pool). The type
/// of constant goes to the formal CPoolRecord \b tag field which can be a:
///   - Primitive value (integer, floating-point)
///   - String literal (pointer to)
///   - Class method (pointer to)
///   - Class field (offset of)
///   - Array length
///   - Data-type (pointer to a descriptor)
///
/// For decompilation, knowing the actual \e constant a byte-code interpreter would need
/// is secondary to knowing what object is being referenced.  So the CPoolRecord can hold a
/// constant value, but generally it provides a data-type associated with the object
/// and a symbol name or other string token naming the object.
class CPoolRecord {
public:
  /// \brief Generic constant pool tag types
  enum {
    primitive=0,	///< Constant \b value of data-type \b type, cpool operator can be eliminated
    string_literal=1,	///< Constant reference to string (passed back as \b byteData)
    class_reference=2,	///< Reference to (system level) class object, \b token holds class name
    pointer_method=3,	///< Pointer to a method, name in \b token, signature in \b type
    pointer_field=4,	///< Pointer to a field, name in \b token, data-type in \b type
    array_length=5,	///< Integer length, \b token is language specific indicator, \b type is integral data-type
    instance_of=6,	///< Boolean value, \b token is language specific indicator, \b type is boolean data-type
    check_cast=7	///< Pointer to object, new name in \b token, new data-type in \b type
  };
  enum {
    is_constructor = 0x1,	///< Referenced method is a constructor
    is_destructor = 0x2		///< Referenced method is a destructor
  };
private:
  friend class ConstantPool;
  uint4 tag;		///< Descriptor of type of the object
  uint4 flags;		///< Additional boolean properties on the record
  string token;		///< Name or token associated with the object
  uintb value;		///< Constant value of the object (if known)
  Datatype *type;	///< Data-type associated with the object
  uint1 *byteData;	///< For string literals, the raw byte data of the string
  int4 byteDataLen;	///< The number of bytes in the data for a string literal
public:
  CPoolRecord(void) { type = (Datatype *)0; byteData = (uint1 *)0; }		///< Construct an empty record
  ~CPoolRecord(void) { if (byteData != (uint1 *)0) delete [] byteData; }	///< Destructor
  uint4 getTag(void) const { return tag; }					///< Get the type of record
  const string &getToken(void) const { return token; }				///< Get name of method or data-type
  const uint1 *getByteData(void) const { return byteData; }			///< Get pointer to string literal data
  int4 getByteDataLength(void) const { return byteDataLen; }			///< Number of bytes of string literal data
  Datatype *getType(void) const { return type; }				///< Get the data-type associated with \b this
  uintb getValue(void) const { return value; }					///< Get the constant value associated with \b this
  bool isConstructor(void) const { return ((flags & is_constructor)!=0); }	///< Is object a constructor method
  bool isDestructor(void) const { return ((flags & is_destructor)!=0); }	///< Is object a destructor method
  void encode(Encoder &encoder) const;						///< Encode \b this to a stream
  void decode(Decoder &decoder,TypeFactory &typegrp);				///< Decode \b this from a stream
};

/// \brief An interface to the pool of \b constant objects for byte-code languages
///
/// This is an abstract base class that acts as a container for CPoolRecords.
/// A \e reference (1 or more integer constants) maps to an individual CPoolRecord.
/// A CPoolRecord object can be queried for using getRecord(), and a new object
/// can be added with putRecord().  Internally, the actual CPoolRecord object
/// is produced by createRecord().
class ConstantPool {
  /// \brief Allocate a new CPoolRecord object, given a \e reference to it
  ///
  /// The object will still need to be initialized but is already associated with the reference.
  /// Any issue with allocation (like a dupicate reference) causes an exception.
  /// \param refs is the \e reference of 1 or more identifying integers
  /// \return the new CPoolRecord
  virtual CPoolRecord *createRecord(const vector<uintb> &refs)=0;
public:
  virtual ~ConstantPool() {}	///< Destructor

  /// \brief Retrieve a constant pool record (CPoolRecord) given a \e reference to it
  ///
  /// \param refs is the \e reference (made up of 1 or more identifying integers)
  /// \return the matching CPoolRecord or NULL if none matches the reference
  virtual const CPoolRecord *getRecord(const vector<uintb> &refs) const=0;

  /// \brief A a new constant pool record to \b this database
  ///
  /// Given the basic constituents of the record, type, name, and data-type, create
  /// a new CPoolRecord object and associate it with the given \e reference.
  /// \param refs is the \e reference (made up of 1 or more identifying integers)
  /// \param tag is the type of record to create
  /// \param tok is the name associated with the object
  /// \param ct is the data-type associated with the object
  void putRecord(const vector<uintb> &refs,uint4 tag,const string &tok,Datatype *ct);

  /// \brief Restore a CPoolRecord given a \e reference and a stream decoder
  ///
  /// A \<cpoolrec> element initializes the new record which is immediately associated
  /// with the \e reference.
  /// \param refs is the \e reference (made up of 1 or more identifying integers)
  /// \param decoder is the given stream decoder
  /// \param typegrp is the TypeFactory used to resolve data-type references in XML
  /// \return the newly allocated and initialized CPoolRecord
  const CPoolRecord *decodeRecord(const vector<uintb> &refs,Decoder &decoder,TypeFactory &typegrp);

  virtual bool empty(void) const=0;		///< Is the container empty of records
  virtual void clear(void)=0;			///< Release any (local) resources

  /// \brief Encode all records in this container to a stream
  ///
  /// (If supported) A \<constantpool> element is written containing \<cpoolrec>
  /// child elements for each CPoolRecord in the container.
  /// \param encoder is the stream encoder
  virtual void encode(Encoder &encoder) const=0;

  /// \brief Restore constant pool records from the given stream decoder
  ///
  /// (If supported) The container is populated with CPoolRecords initialized
  /// from a \<constantpool> element.
  /// \param decoder is the given stream decoder
  /// \param typegrp is the TypeFactory used to resolve data-type references in the XML
  virtual void decode(Decoder &decoder,TypeFactory &typegrp)=0;
};

/// \brief An implementation of the ConstantPool interface storing records internally in RAM
///
/// The CPoolRecord objects are held directly in a map container. This class can be used
/// as a stand-alone ConstantPool that holds all its records in RAM. Or, it can act as
/// a local CPoolRecord cache for some other implementation.
class ConstantPoolInternal : public ConstantPool {

  /// \brief A cheap (efficient) placeholder for a \e reference to a constant pool record
  ///
  /// A \b reference can be an open-ended number of (1 or more) integers. In practice, the
  /// most integers we see in a reference is two.  So this is a slightly more efficient
  /// container than an open-ended vector.
  /// The field \b a is the first integer, the field \b b is the second integer, or zero
  /// if there is no second integer. The references are ordered lexicographically.
  /// The class also serves to serialize/deserialize references from XML
  class CheapSorter {
  public:
    uintb a;			///< The first integer in a \e reference
    uintb b;			///< The second integer in a \e reference (or zero)
    CheapSorter(void) { a = 0; b = 0; }	///< Construct a zero reference
    CheapSorter(const CheapSorter &op2) { a = op2.a; b = op2.b; }	///< Copy constructor
    CheapSorter(const vector<uintb> &refs) { a = refs[0]; b = (refs.size() > 1) ? refs[1] : 0; } ///< Construct from an array of integers

    /// \brief Lexicographic comparison
    ///
    /// \param op2 is the reference to compare with \b this
    /// \return \b true if \b this should be ordered before the other reference
    bool operator<(const CheapSorter &op2) const {
      if (a != op2.a) return (a<op2.a);
      return (b < op2.b);
    }

    /// \brief Convert the reference back to a formal array of integers
    ///
    /// \param refs is the provided container of integers
    void apply(vector<uintb> &refs) const { refs.push_back(a); refs.push_back(b); }

    void encode(Encoder &encoder) const;	///< Encode the \e reference to a stream
    void decode(Decoder &decoder);		///< Decode the \e reference from a stream
  };
  map<CheapSorter,CPoolRecord> cpoolMap;	///< A map from \e reference to constant pool record
  virtual CPoolRecord *createRecord(const vector<uintb> &refs);
public:
  virtual const CPoolRecord *getRecord(const vector<uintb> &refs) const;
  virtual bool empty(void) const { return cpoolMap.empty(); }
  virtual void clear(void) { cpoolMap.clear(); }
  virtual void encode(Encoder &encoder) const;
  virtual void decode(Decoder &decoder,TypeFactory &typegrp);
};

} // End namespace ghidra
#endif
