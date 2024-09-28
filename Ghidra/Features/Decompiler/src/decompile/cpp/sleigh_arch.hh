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
/// \file sleigh_arch.hh
/// \brief Architecture objects that use a Translate object derived from Sleigh

#ifndef __SLEIGH_ARCH_HH__
#define __SLEIGH_ARCH_HH__

#include "filemanage.hh"
#include "architecture.hh"
#include "sleigh.hh"

namespace ghidra {

extern AttributeId ATTRIB_DEPRECATED;	///< Marshaling attribute "deprecated"
extern AttributeId ATTRIB_ENDIAN;	///< Marshaling attribute "endian"
extern AttributeId ATTRIB_PROCESSOR;	///< Marshaling attribute "processor"
extern AttributeId ATTRIB_PROCESSORSPEC;	///< Marshaling attribute "processorspec"
extern AttributeId ATTRIB_SLAFILE;	///< Marshaling attribute "slafile"
extern AttributeId ATTRIB_SPEC;		///< Marshaling attribute "spec"
extern AttributeId ATTRIB_TARGET;	///< Marshaling attribute "target"
extern AttributeId ATTRIB_VARIANT;	///< Marshaling attribute "variant"
extern AttributeId ATTRIB_VERSION;	///< Marshaling attribute "version"

extern ElementId ELEM_COMPILER;		///< Marshaling element \<compiler>
extern ElementId ELEM_DESCRIPTION;	///< Marshaling element \<description>
extern ElementId ELEM_LANGUAGE;		///< Marshaling element \<language>
extern ElementId ELEM_LANGUAGE_DEFINITIONS;	///< Marshaling element \<language_definitions>

/// \brief Contents of a \<compiler> tag in a .ldefs file
///
/// This class describes a compiler specification file as referenced by the Sleigh language subsystem.
class CompilerTag {
  string name;          ///< (Human readable) name of the compiler
  string spec;          ///< cspec file for this compiler
  string id;            ///< Unique id for this compiler
public:
  CompilerTag(void) {}	///< Constructor
  void decode(Decoder &decoder);	///< Restore the record from an XML stream
  const string &getName(void) const { return name; }	///< Get the human readable name of the spec
  const string &getSpec(void) const { return spec; }	///< Get the file-name
  const string &getId(void) const { return id; }	///< Get the string used as part of \e language \e id
};

/// \brief Contents of the \<language> tag in a .ldefs file
///
/// This class contains meta-data describing a single processor and the set of
/// files used to analyze it.  Ghidra requires a compiled SLEIGH specification file
/// (.sla), a processor specification file (.pspec), and a compiler specification file (.cspec)
/// in order to support disassembly/decompilation of a processor.  This class supports
/// a single processor, as described by a single SLEIGH file and processor spec.  Multiple
/// compiler specifications can be given for the single processor.
class LanguageDescription {
  string processor;		///< Name of processor
  bool isbigendian;		///< Set to \b true if this processor is \e big-endian
  int4 size;			///< Size of address bus in bits
  string variant;		///< Name of processor variant or "default"
  string version;		///< Version of the specification
  string slafile;		///< Name of .sla file for processor
  string processorspec;		///< Name of .pspec file
  string id;			///< Unique id for this language
  string description;		///< Human readable description of this language
  bool deprecated;		///< Set to \b true if the specification is considered \e deprecated
  vector<CompilerTag> compilers;	///< List of compiler specifications compatible with this processor
  vector<TruncationTag> truncations;	///< Address space truncations required by this processor
public:
  LanguageDescription(void) {}					///< Constructor
  void decode(Decoder &decoder);				///< Parse \b this description from a stream
  const string &getProcessor(void) const { return processor; }	///< Get the name of the processor
  bool isBigEndian(void) const { return isbigendian; }		///< Return \b true if the processor is big-endian
  int4 getSize(void) const { return size; }			///< Get the size of the address bus
  const string &getVariant(void) const { return variant; }	///< Get the processor variant
  const string &getVersion(void) const { return version; }	///< Get the processor version
  const string &getSlaFile(void) const { return slafile; }	///< Get filename of the SLEIGH specification
  const string &getProcessorSpec(void) const { return processorspec; }	///< Get the filename of the processor specification
  const string &getId(void) const { return id; }		///< Get the \e language \e id string associated with this processor
  const string &getDescription(void) const { return description; }	///< Get a description of the processor
  bool isDeprecated(void) const { return deprecated; }		///< Return \b true if this specification is deprecated
  const CompilerTag &getCompiler(const string &nm) const;	///< Get compiler specification of the given name
  int4 numCompilers(void) const { return compilers.size(); }	///< Get the number of compiler records
  const CompilerTag &getCompiler(int4 i) const { return compilers[i]; }	///< Get the i-th compiler record
  int4 numTruncations(void) const { return truncations.size(); }	///< Get the number of truncation records
  const TruncationTag &getTruncation(int4 i) const { return truncations[i]; }	///< Get the i-th truncation record
};

/// \brief An Architecture that uses the decompiler's native SLEIGH translation engine
///
/// Any Architecture derived from \b this knows how to natively read in:
///   - a compiled SLEIGH specification (.sla)
///   - a processor specification file (.pspec), and
///   - a compiler specification file (.cspec)
///
/// Generally a \e language \e id (i.e. x86:LE:64:default) is provided, then this
/// object is able to automatically load in configuration and construct the Translate object.
class SleighArchitecture : public Architecture {
  static map<int4,Sleigh> translators;		///< Map from language index to instantiated translators
  static vector<LanguageDescription> description;	///< List of languages we know about
  int4 languageindex;					///< Index (within LanguageDescription array) of the active language
  string filename;					///< Name of active load-image file
  string target;					///< The \e language \e id of the active load-image
  static void loadLanguageDescription(const string &specfile,ostream &errs);
  bool isTranslateReused(void);				///< Test if last Translate object can be reused
protected:
  ostream *errorstream;					///< Error stream associated with \b this SleighArchitecture
  // buildLoader must be filled in by derived class
  static void collectSpecFiles(ostream &errs);		///< Gather specification files in normal locations
  virtual Translate *buildTranslator(DocumentStorage &store);
  virtual PcodeInjectLibrary *buildPcodeInjectLibrary(void);
  virtual void buildTypegrp(DocumentStorage &store);
  virtual void buildCoreTypes(DocumentStorage &store);
  virtual void buildCommentDB(DocumentStorage &store);
  virtual void buildStringManager(DocumentStorage &store);
  virtual void buildConstantPool(DocumentStorage &store);
  virtual void buildContext(DocumentStorage &store);
  virtual void buildSymbols(DocumentStorage &store);
  virtual void buildSpecFile(DocumentStorage &store);
  virtual void modifySpaces(Translate *trans);
  virtual void resolveArchitecture(void);
public:
  SleighArchitecture(const string &fname,const string &targ,ostream *estream);	///< Construct given executable file
  const string &getFilename(void) const { return filename; }	///< Get the executable filename
  const string &getTarget(void) const { return target; }	///< Get the \e language \e id of the active processor
  void encodeHeader(Encoder &encoder) const;			///< Encode basic attributes of the active executable
  void restoreXmlHeader(const Element *el);			///< Restore from basic attributes of an executable
  virtual void printMessage(const string &message) const { *errorstream << message << endl; }
  virtual ~SleighArchitecture(void);
  virtual string getDescription(void) const;

  static string normalizeProcessor(const string &nm);		///< Try to recover a \e language \e id processor field
  static string normalizeEndian(const string &nm);		///< Try to recover a \e language \e id endianness field
  static string normalizeSize(const string &nm);		///< Try to recover a \e language \e id size field
  static string normalizeArchitecture(const string &nm);	///< Try to recover a \e language \e id string
  static void scanForSleighDirectories(const string &rootpath);
  static const vector<LanguageDescription> &getDescriptions(void);	///< Get list of all known language descriptions
  static void shutdown(void);					///< Shutdown all Translate objects and free global resources.
  static FileManage specpaths;					///< Known directories that contain .ldefs files.
};

} // End namespace ghidra
#endif
