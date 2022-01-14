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
/// \file sleighbase.hh
/// \brief Base class for applications that process SLEIGH format specifications
#ifndef __SLEIGHBASE__
#define __SLEIGHBASE__

#include "translate.hh"
#include "slghsymbol.hh"

/// \brief class for recording source file information for SLEIGH constructors.

///
/// A SLEIGH specification may contain many source files.  This class is
/// used to associate each constructor in a SLEIGH language to the source
/// file where it is defined. This information is useful when debugging
/// SLEIGH specifications.  Sourcefiles are assigned a numeric index and
/// the mapping from indices to filenames is written to the generated .sla
/// file.  For each constructor, the data written to the .sla file includes
/// the source file index.
class SourceFileIndexer {
public:
    SourceFileIndexer() {leastUnusedIndex = 0;}
    ~SourceFileIndexer(void) { }
    ///Returns the index of the file.  If the file is not in the index it is added.
    int4 index(const string filename);
	int4 getIndex(const string);  ///< get the index of a file.  Error if the file is not in the index.
	string getFilename(int4);     ///< get the filename corresponding to an index
    void restoreXml(const Element *el); ///< read a stored index mapping from an XML file
	void saveXml(ostream&) const;       ///< save the index mapping to an XML file

private:
	int4 leastUnusedIndex;  ///< one-up count for assigning indices to files
	map<int4, string> indexToFile;  ///< map from indices to files
	map<string, int4> fileToIndex;  ///< map from files to indices
};

/// \brief Common core of classes that read or write SLEIGH specification files natively.

///
/// This class represents what's in common across the SLEIGH infrastructure between:
///   - Reading the various SLEIGH specification files
///   - Building and writing out SLEIGH specification files
class SleighBase : public Translate {
  static const int4 SLA_FORMAT_VERSION;	///< Current version of the .sla file read/written by SleighBash
  vector<string> userop;		///< Names of user-define p-code ops for \b this Translate object
  map<VarnodeData,string> varnode_xref;	///< A map from Varnodes in the \e register space to register names
protected:
  SubtableSymbol *root;		///< The root SLEIGH decoding symbol
  SymbolTable symtab;		///< The SLEIGH symbol table
  uint4 maxdelayslotbytes;	///< Maximum number of bytes in a delay-slot directive
  uint4 unique_allocatemask;	///< Bits that are guaranteed to be zero in the unique allocation scheme
  uint4 numSections;		///< Number of \e named sections
  SourceFileIndexer indexer;    ///< source file index used when generating SLEIGH constructor debug info
  void buildXrefs(vector<string> &errorPairs);	///< Build register map. Collect user-ops and context-fields.
  void reregisterContext(void);	///< Reregister context fields for a new executable
  void restoreXml(const Element *el);	///< Read a SLEIGH specification from XML
public:
  static const uint4 MAX_UNIQUE_SIZE;    ///< Maximum size of a varnode in the unique space (should match value in SleighBase.java)
  SleighBase(void);		///< Construct an uninitialized translator
  bool isInitialized(void) const { return (root != (SubtableSymbol *)0); }	///< Return \b true if \b this is initialized
  virtual ~SleighBase(void) {}	///< Destructor
  virtual const VarnodeData &getRegister(const string &nm) const;
  virtual string getRegisterName(AddrSpace *base,uintb off,int4 size) const;
  virtual void getAllRegisters(map<VarnodeData,string> &reglist) const;
  virtual void getUserOpNames(vector<string> &res) const;

  SleighSymbol *findSymbol(const string &nm) const { return symtab.findSymbol(nm); }	///< Find a specific SLEIGH symbol by name in the current scope
  SleighSymbol *findSymbol(uintm id) const { return symtab.findSymbol(id); }	///< Find a specific SLEIGH symbol by id
  SleighSymbol *findGlobalSymbol(const string &nm) const { return symtab.findGlobalSymbol(nm); }	///< Find a specific global SLEIGH symbol by name
  void saveXml(ostream &s) const;	///< Write out the SLEIGH specification as an XML \<sleigh> tag.
};

#endif
