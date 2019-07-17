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
/// \file loadimage.hh
/// \brief Classes and API for accessing a binary load image

#ifndef __CPUI_LOADIMAGE__
#define __CPUI_LOADIMAGE__

#include "address.hh"

/// \brief Exception indicating data was not available
///
/// This exception is thrown when a request for load image
/// data cannot be met, usually because the requested address
/// range is not in the image.
struct DataUnavailError : public LowlevelError {
  DataUnavailError(const string &s) : LowlevelError(s) {} ///< Instantiate with an explanatory string
};

/// \brief A record indicating a function symbol
///
/// This is a lightweight object holding the Address and name of a function
struct LoadImageFunc {
  Address address;	///< Start of function
  string name;		///< Name of function
};

/// \brief A record describing a section bytes in the executable
///
/// A lightweight object specifying the location and size of the section and basic properties
struct LoadImageSection {
  /// Boolean properties a section might have
  enum {
    unalloc = 1,		///< Not allocated in memory (debug info)
    noload = 2,			///< uninitialized section
    code = 4,			///< code only
    data = 8,			///< data only
    readonly = 16		///< read only section
  };
  Address address;		///< Starting address of section
  uintb size;			///< Number of bytes in section
  uint4 flags;			///< Properties of the section
};

/// \brief An interface into a particular binary executable image
///
/// This class provides the abstraction needed by the decompiler
/// for the numerous load file formats used to encode binary
/// executables.  The data encoding the machine instructions
/// for the executable can be accessed via the addresses where
/// that data would be loaded into RAM.
/// Properties other than the main data and instructions of the
/// binary are not supposed to repeatedly queried through this
/// interface. This information is intended to be read from
/// this class exactly once, during initialization, and used to
/// populate the main decompiler database. This class currently
/// has only rudimentary support for accessing such properties.
class LoadImage {
protected:
  string filename;		///< Name of the loadimage
public:
  LoadImage(const string &f);	///< LoadImage constructor
  virtual ~LoadImage(void);	///< LoadImage destructor
  const string &getFileName(void) const; ///< Get the name of the LoadImage
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr)=0; ///< Get data from the LoadImage
  virtual void openSymbols(void) const; ///< Prepare to read symbols
  virtual void closeSymbols(void) const; ///< Stop reading symbols
  virtual bool getNextSymbol(LoadImageFunc &record) const; ///< Get the next symbol record
  virtual void openSectionInfo(void) const; ///< Prepare to read section info
  virtual void closeSectionInfo(void) const; ///< Stop reading section info
  virtual bool getNextSection(LoadImageSection &sec) const; ///< Get info on the next section
  virtual void getReadonly(RangeList &list) const; ///< Return list of \e readonly address ranges
  virtual string getArchType(void) const=0; ///< Get a string indicating the architecture type
  virtual void adjustVma(long adjust)=0; ///< Adjust load addresses with a global offset
  uint1 *load(int4 size,const Address &addr);	///< Load a chunk of image
};

/// \brief A simple raw binary loadimage
///
/// This is probably the simplest loadimage.  Bytes from the image are read directly from a file stream.
/// The address associated with each byte is determined by a single value, the vma, which is the address
/// of the first byte in the file.  No symbols or sections are supported
class RawLoadImage : public LoadImage {
  uintb vma;			///< Address of first byte in the file
  ifstream *thefile;		///< Main file stream for image
  uintb filesize;		///< Total number of bytes in the loadimage/file
  AddrSpace *spaceid;		///< Address space that the file bytes are mapped to
public:
  RawLoadImage(const string &f); ///< RawLoadImage constructor
  void attachToSpace(AddrSpace *id) { spaceid = id; }	///< Attach the raw image to a particular space
  void open(void);					///< Open the raw file for reading
  virtual ~RawLoadImage(void);				///< RawLoadImage destructor
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr);
  virtual string getArchType(void) const;
  virtual void adjustVma(long adjust);
};

/// For the base class there is no relevant initialization except
/// the name of the image.
/// \param f is the name of the image
inline LoadImage::LoadImage(const string &f) {
  filename = f;
}

/// The destructor for the load image object.
inline LoadImage::~LoadImage(void) {
}

/// The loadimage is usually associated with a file. This routine
/// retrieves the name as a string.
/// \return the name of the image
inline const string &LoadImage::getFileName(void) const {
  return filename;
}

/// This routine should read in and parse any symbol information
/// that the load image contains about executable.  Once this
/// method is called, individual symbol records are read out
/// using the getNextSymbol() method.
inline void LoadImage::openSymbols(void) const {
}

/// Once all the symbol information has been read out from the
/// load image via the openSymbols() and getNextSymbol() calls,
/// the application should call this method to free up resources
/// used in parsing the symbol information.
inline void LoadImage::closeSymbols(void) const {
}

/// This method is used to read out an individual symbol record,
/// LoadImageFunc, from the load image.  Right now, the only
/// information that can be read out are function starts and the
/// associated function name.  This method can be called repeatedly
/// to iterate through all the symbols, until it returns \b false.
/// This indicates the end of the symbols.
/// \param record is a reference to the symbol record to be filled in
/// \return \b true if there are more records to read
inline bool LoadImage::getNextSymbol(LoadImageFunc &record) const {
  return false;
}

/// This method initializes iteration over all the sections of
/// bytes that are mapped by the load image.  Once this is called,
/// information on individual sections should be read out with
/// the getNextSection() method.
inline void LoadImage::openSectionInfo(void) const {
}

/// Once all the section information is read from the load image
/// using the getNextSection() method, this method should be
/// called to free up any resources used in parsing the section info.
inline void LoadImage::closeSectionInfo(void) const {
}

/// This method is used to read out a record that describes a
/// single section of bytes mapped by the load image. This
/// method can be called repeatedly until it returns \b false,
/// to get info on additional sections.
/// \param record is a reference to the info record to be filled in
/// \return \b true if there are more records to read
inline bool LoadImage::getNextSection(LoadImageSection &record) const {
  return false;
}

/// This method should read out information about \e all
/// address ranges within the load image that are known to be
/// \b readonly.  This method is intended to be called only
/// once, so all information should be written to the passed
/// RangeList object.
/// \param list is where readonly info will get put
inline void LoadImage::getReadonly(RangeList &list) const {
}

/// \fn void LoadImage::adjustVma(long adjust)
/// Most load image formats automatically encode information
/// about the true loading address(es) for the data in the image.
/// But if this is missing or incorrect, this routine can be
/// used to make a global adjustment to the load address. Only
/// one adjustment is made across \e all addresses in the image.
/// The offset passed to this method is added to the stored
/// or default value for any address queried in the image.
/// This is most often used in a \e raw binary file format.  In
/// this case, the entire executable file is intended to be
/// read straight into RAM, as one contiguous chunk, in order to
/// be executed.  In the absence of any other info, the first
/// byte of the image file is loaded at offset 0. This method
/// then would adjust the load address of the first byte.
/// \param adjust is the offset amount to be added to default values

/// \fn string LoadImage::getArchType(void) const
/// The load image class is intended to be a generic front-end
/// to the large variety of load formats in use.  This method
/// should return a string that identifies the particular
/// architecture this particular image is intended to run on.
/// It is currently the responsibility of any derived LoadImage
/// class to establish a format for this string, but it should
/// generally contain some indication of the operating system
/// and the processor.
/// \return the identifier string

/// \fn void LoadImage::loadFill(uint1 *ptr,int4 size,const Address &addr)
/// This is the \e core routine of a LoadImage.  Given a particular
/// address range, this routine retrieves the exact byte values
/// that are stored at that address when the executable is loaded
/// into RAM.  The caller must supply a pre-allocated array
/// of bytes where the returned bytes should be stored.  If the
/// requested address range does not exist in the image, or
/// otherwise can't be retrieved, this method throws an
/// DataUnavailError exception.
/// \param ptr points to where the resulting bytes will be stored
/// \param size is the number of bytes to retrieve from the image
/// \param addr is the starting address of the bytes to retrieve

#endif
