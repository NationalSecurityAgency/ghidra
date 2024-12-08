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
/// \file architecture.hh
/// \brief Architecture and associated classes that help manage a single processor architecture and load image
#ifndef __ARCHITECTURE_HH__
#define __ARCHITECTURE_HH__

#include "capability.hh"
#include "varmap.hh"
#include "action.hh"
#include "database.hh"
#include "pcodeinject.hh"
#include "fspec.hh"
#include "translate.hh"
#include "loadimage.hh"
#include "globalcontext.hh"
#include "comment.hh"
#include "stringmanage.hh"
#include "userop.hh"
#include "options.hh"
#include "transform.hh"
#include "prefersplit.hh"

namespace ghidra {

#ifdef CPUI_STATISTICS
/// \brief Class for collecting statistics while processing over multiple functions
///
/// As Funcdata objects are transformed, they get fed to the process() method
/// to accumulate statistics over the whole run.  Results are printed with printResults()
class Statistics {
  uintb numfunc;		///< Number of functions processed
  uintb numvar;			///< Number of Varnodes analyzed
  uintb coversum;		///< Number of Varnodes with non-empty covers
  uintb coversumsq;		///< Internal sum for variance of coversum
  uintb lastcastcount;		///< Number of casts since processing last function
  uintb castcount;		///< Total number of casts
  uintb castcountsq;		///< Internal sum for variance of castcount
  //void process_cover(const Funcdata &data);
  void process_cast(const Funcdata &data);	///< Count casts for function
public:
  Statistics(void);		///< Construct initializing counts
  ~Statistics(void);		///< Destructor
  void countCast(void) { castcount += 1; }	///< Count a single cast
  void process(const Funcdata &fd);	///< Accumulate statistics for one function
  void printResults(ostream &s);	///< Display accumulated statistics
};

#endif

class Architecture;

extern AttributeId ATTRIB_ADDRESS;	///< Marshaling attribute "address"
extern AttributeId ATTRIB_ADJUSTVMA;	///< Marshaling attribute "adjustvma"
extern AttributeId ATTRIB_ENABLE;	///< Marshaling attribute "enable"
extern AttributeId ATTRIB_GROUP;	///< Marshaling attribute "group"
extern AttributeId ATTRIB_GROWTH;	///< Marshaling attribute "growth"
extern AttributeId ATTRIB_KEY;		///< Marshaling attribute "key"
extern AttributeId ATTRIB_LOADERSYMBOLS;	///< Marshaling attribute "loadersymbols"
extern AttributeId ATTRIB_PARENT;	///< Marshaling attribute "parent"
extern AttributeId ATTRIB_REGISTER;	///< Marshaling attribute "register"
extern AttributeId ATTRIB_REVERSEJUSTIFY;	///< Marshaling attribute "reversejustify"
extern AttributeId ATTRIB_SIGNEXT;	///< Marshaling attribute "signext"
extern AttributeId ATTRIB_STYLE;	///< Marshaling attribute "style"

extern ElementId ELEM_ADDRESS_SHIFT_AMOUNT;	///< Marshaling element \<address_shift_amount>
extern ElementId ELEM_AGGRESSIVETRIM;		///< Marshaling element \<aggressivetrim>
extern ElementId ELEM_COMPILER_SPEC;		///< Marshaling element \<compiler_spec>
extern ElementId ELEM_DATA_SPACE;		///< Marshaling element \<data_space>
extern ElementId ELEM_DEFAULT_MEMORY_BLOCKS;	///< Marshaling element \<default_memory_blocks>
extern ElementId ELEM_DEFAULT_PROTO;		///< Marshaling element \<default_proto>
extern ElementId ELEM_DEFAULT_SYMBOLS;		///< Marshaling element \<default_symbols>
extern ElementId ELEM_EVAL_CALLED_PROTOTYPE;	///< Marshaling element \<eval_called_prototype>
extern ElementId ELEM_EVAL_CURRENT_PROTOTYPE;	///< Marshaling element \<eval_current_prototype>
extern ElementId ELEM_EXPERIMENTAL_RULES;	///< Marshaling element \<experimental_rules>
extern ElementId ELEM_FLOWOVERRIDELIST;		///< Marshaling element \<flowoverridelist>
extern ElementId ELEM_FUNCPTR;			///< Marshaling element \<funcptr>
extern ElementId ELEM_GLOBAL;			///< Marshaling element \<global>
extern ElementId ELEM_INCIDENTALCOPY;		///< Marshaling element \<incidentalcopy>
extern ElementId ELEM_INFERPTRBOUNDS;		///< Marshaling element \<inferptrbounds>
extern ElementId ELEM_MODELALIAS;		///< Marshaling element \<modelalias>
extern ElementId ELEM_NOHIGHPTR;		///< Marshaling element \<nohighptr>
extern ElementId ELEM_PROCESSOR_SPEC;		///< Marshaling element \<processor_spec>
extern ElementId ELEM_PROGRAMCOUNTER;		///< Marshaling element \<programcounter>
extern ElementId ELEM_PROPERTIES;		///< Marshaling element \<properties>
extern ElementId ELEM_PROPERTY;			///< Marshaling element \<property>
extern ElementId ELEM_READONLY;			///< Marshaling element \<readonly>
extern ElementId ELEM_REGISTER_DATA;		///< Marshaling element \<register_data>
extern ElementId ELEM_RULE;			///< Marshaling element \<rule>
extern ElementId ELEM_SAVE_STATE;		///< Marshaling element \<save_state>
extern ElementId ELEM_SEGMENTED_ADDRESS;	///< Marshaling element \<segmented_address>
extern ElementId ELEM_SPACEBASE;		///< Marshaling element \<spacebase>
extern ElementId ELEM_SPECEXTENSIONS;		///< Marshaling element \<specextensions>
extern ElementId ELEM_STACKPOINTER;		///< Marshaling element \<stackpointer>
extern ElementId ELEM_VOLATILE;			///< Marshaling element \<volatile>

/// \brief Abstract extension point for building Architecture objects
///
/// Decompilation hinges on initially recognizing the format of code then
/// bootstrapping into discovering the processor etc.  This is the base class
/// for the different extensions that perform this process.  Each extension
/// implements the buildArchitecture() method as the formal entry point
/// for the bootstrapping process.
class ArchitectureCapability : public CapabilityPoint {
  static const uint4 majorversion;			///< Current major version of decompiler
  static const uint4 minorversion;			///< Current minor version of decompiler
  static vector<ArchitectureCapability *> thelist;	///< The list of registered extensions
protected:
  string name;						///< Identifier for this capability
public:
  const string &getName(void) const { return name; }	///< Get the capability identifier
  virtual void initialize(void);			///< Do specialized initialization

  /// \brief Build an Architecture given a raw file or data
  ///
  /// This is implemented by each separate extension. The method is handed
  /// a \e filename and possibly external target information and must build
  /// the Architecture object, initializing all the major subcomponents, using just this info.
  /// \param filename is the path to the executable file to examine
  /// \param target if non-empty is a language id string
  /// \param estream is an output stream for error messages
  virtual Architecture *buildArchitecture(const string &filename,const string &target,ostream *estream)=0;

  /// \brief Determine if this extension can handle this file
  ///
  /// \param filename is the name of the file to examine
  /// \return \b true is \b this extension is suitable for analyzing the file
  virtual bool isFileMatch(const string &filename) const=0;

  /// \brief Determine is this extension can handle this XML document
  ///
  /// If a file to analyze is XML based, this method examines the XML parse
  /// to determine if \b this extension can understand the document
  /// \param doc is the parsed XML document
  /// \return \b true if \b this extension understands the XML
  virtual bool isXmlMatch(Document *doc) const=0;

  static ArchitectureCapability *findCapability(const string &filename);	///< Find an extension to process a file
  static ArchitectureCapability *findCapability(Document *doc);		///< Find an extension to process an XML document
  static ArchitectureCapability *getCapability(const string &name);	///< Get a capability by name
  static void sortCapabilities(void);					///< Sort extensions
  static uint4 getMajorVersion(void) { return majorversion; }		///< Get \e major decompiler version
  static uint4 getMinorVersion(void) { return minorversion; }		///< Get \e minor decompiler version
};

/// \brief Manager for all the major decompiler subsystems
///
/// An instantiation is tailored to a specific LoadImage,
/// processor, and compiler spec. This class is the \e owner of
/// the LoadImage, Translate, symbols (Database), PrintLanguage, etc.
/// This class also holds numerous configuration parameters for the analysis process
class Architecture : public AddrSpaceManager {
public:
  string archid;		///< ID string uniquely describing this architecture

				// Configuration data
  int4 trim_recurse_max;	///< How many levels to let parameter trims recurse
  int4 max_implied_ref;		///< Maximum number of references to an implied var
  int4 max_term_duplication;	///< Max terms duplicated without a new variable
  int4 max_basetype_size;	///< Maximum size of an "integer" type before creating an array type
  int4 min_funcsymbol_size;	///< Minimum size of a function symbol
  uint4 max_jumptable_size;	///< Maximum number of entries in a single JumpTable
  bool aggressive_ext_trim;	///< Aggressively trim inputs that look like they are sign extended
  bool readonlypropagate;	///< true if readonly values should be treated as constants
  bool infer_pointers;		///< True if we should infer pointers from constants that are likely addresses
  bool analyze_for_loops;	///< True if we should attempt conversion of \e whiledo loops to \e for loops
  bool nan_ignore_all;		///< True if we should ignore NaN operations, i.e. nan() always returns false
  bool nan_ignore_compare;	///< True if we should ignore NaN operations protecting floating-point comparisons
  vector<AddrSpace *> inferPtrSpaces;	///< Set of address spaces in which a pointer constant is inferable
  int4 funcptr_align;		///< How many bits of alignment a function ptr has
  uint4 flowoptions;            ///< options passed to flow following engine
  uint4 max_instructions;	///< Maximum instructions that can be processed in one function
  int4 alias_block_level;	///< Aliases blocked by 0=none, 1=struct, 2=array, 3=all
  uint4 split_datatype_config;	///< Toggle for data-types splitting: Bit 0=structs, 1=arrays, 2=pointers
  vector<Rule *> extra_pool_rules; ///< Extra rules that go in the main pool (cpu specific, experimental)

  Database *symboltab;		///< Memory map of global variables and functions
  ContextDatabase *context;	///< Map from addresses to context settings
  map<string,ProtoModel *> protoModels; ///< Parsed forms of possible prototypes
  ProtoModel *defaultfp;	///< Parsed form of default prototype
  VarnodeData defaultReturnAddr;	///< Default storage location of return address (for current function)
  ProtoModel *evalfp_current;	///< Function proto to use when evaluating current function
  ProtoModel *evalfp_called;	///< Function proto to use when evaluating called functions
  TypeFactory *types;		///< List of types for this binary
  const Translate *translate;	///< Translation method for this binary
  LoadImage *loader;		///< Method for loading portions of binary
  PcodeInjectLibrary *pcodeinjectlib;	///< Pcode injection manager
  RangeList nohighptr;          ///< Ranges for which high-level pointers are not possible
  CommentDatabase *commentdb;	///< Comments for this architecture
  StringManager *stringManager;	///< Manager of decoded strings
  ConstantPool *cpool;		///< Deferred constant values
  PrintLanguage *print;	        ///< Current high-level language printer
  vector<PrintLanguage *> printlist;	///< List of high-level language printers supported
  OptionDatabase *options;	///< Options that can be configured
  vector<TypeOp *> inst;	///< Registered p-code instructions
  UserOpManage userops;		///< Specifically registered user-defined p-code ops
  vector<PreferSplitRecord> splitrecords; ///< registers that we would prefer to see split for this processor
  vector<LanedRegister> lanerecords;	///< Vector registers that have preferred lane sizes
  ActionDatabase allacts;	///< Actions that can be applied in this architecture
  bool loadersymbols_parsed;	///< True if loader symbols have been read
#ifdef CPUI_STATISTICS
  Statistics *stats;		///< Statistics collector
#endif
#ifdef OPACTION_DEBUG
  ostream *debugstream;		///< The error console
#endif
  Architecture(void);		///< Construct an uninitialized Architecture
  void init(DocumentStorage &store); ///< Load the image and configure architecture
  void resetDefaultsInternal(void);	///< Reset default values for options specific to Architecture
  void resetDefaults(void);		///< Reset defaults values for options owned by \b this
  ProtoModel *getModel(const string &nm) const;		///< Get a specific PrototypeModel
  bool hasModel(const string &nm) const;		///< Does this Architecture have a specific PrototypeModel
  ProtoModel *createUnknownModel(const string &modelName);	///< Create a model for an unrecognized name
  bool highPtrPossible(const Address &loc,int4 size) const; ///< Are pointers possible to the given location?
  AddrSpace *getSpaceBySpacebase(const Address &loc,int4 size) const; ///< Get space associated with a \e spacebase register
  const LanedRegister *getLanedRegister(const Address &loc,int4 size) const;	///< Get LanedRegister associated with storage
  int4 getMinimumLanedRegisterSize(void) const;		///< Get the minimum size of a laned register in bytes
  void setDefaultModel(ProtoModel *model);		///< Set the default PrototypeModel
  void clearAnalysis(Funcdata *fd);			///< Clear analysis specific to a function
  void readLoaderSymbols(const string &delim);		 ///< Read any symbols from loader into database
  void collectBehaviors(vector<OpBehavior *> &behave) const;	///< Provide a list of OpBehavior objects
  SegmentOp *getSegmentOp(AddrSpace *spc) const;	///< Retrieve the \e segment op for the given space if any
  void setPrototype(const PrototypePieces &pieces);	///< Set the prototype for a particular function
  void setPrintLanguage(const string &nm);		///< Establish a particular output language
  void globalify(void);					///< Mark \e all spaces as global
  void decodeFlowOverride(Decoder &decoder);		///< Decode flow overrides from a stream
  virtual ~Architecture(void);				///< Destructor

  /// \brief Get a string describing \b this architecture
  /// \return the description
  virtual string getDescription(void) const { return archid; }

  /// \brief Print an error message to console
  ///
  /// Write the given message to whatever the registered error stream is
  /// \param message is the error message
  virtual void printMessage(const string &message) const=0;
  virtual void encode(Encoder &encoder) const;		///< Encode \b this architecture to a stream
  virtual void restoreXml(DocumentStorage &store);	///< Restore the Architecture state from XML documents
  virtual void nameFunction(const Address &addr,string &name) const;	///< Pick a default name for a function
#ifdef OPACTION_DEBUG
  void setDebugStream(ostream *s) { debugstream = s; }	///< Establish the debug console stream
  void printDebug(const string &message) const { *debugstream << message << endl; }	///< Print message to the debug stream
#endif
protected:
  void addSpacebase(AddrSpace *basespace,const string &nm,const VarnodeData &ptrdata,
		    int4 truncSize,bool isreversejustified,bool stackGrowth,bool isFormal);
  void addNoHighPtr(const Range &rng); ///< Add a new region where pointers do not exist

  // Factory routines for building this architecture
  virtual Scope *buildDatabase(DocumentStorage &store);		///< Build the database and global scope for this executable

  /// \brief Build the Translator object
  ///
  /// This builds the main disassembly component for the Architecture
  /// This does \e not initially the engine for a specific processor.
  /// \param store may hold configuration information
  /// \return the Translate object
  virtual Translate *buildTranslator(DocumentStorage &store)=0;

  /// \brief Build the LoadImage object and load the executable image
  ///
  /// \param store may hold configuration information
  virtual void buildLoader(DocumentStorage &store)=0;

  /// \brief Build the injection library
  ///
  /// This creates the container for p-code injections. It is initially empty.
  /// \return the PcodeInjectLibrary object
  virtual PcodeInjectLibrary *buildPcodeInjectLibrary(void)=0;

  /// \brief Build the data-type factory/container
  ///
  /// Build the TypeFactory object specific to \b this Architecture and
  /// prepopulate it with the \e core types.
  /// \param store contains possible configuration information
  virtual void buildTypegrp(DocumentStorage &store)=0;

  /// \brief Add core primitive data-types
  ///
  /// Core types may be pulled from the configuration information, or default core types are used.
  /// \param store contains possible configuration information
  virtual void buildCoreTypes(DocumentStorage &store)=0;

  /// \brief Build the comment database
  ///
  /// Build the container that holds comments in \b this Architecture.
  /// \param store may hold configuration information
  virtual void buildCommentDB(DocumentStorage &store)=0;

  /// \brief Build the string manager
  ///
  /// Build container that holds decoded strings for \b this Architecture.
  /// \param store may hold configuration information
  virtual void buildStringManager(DocumentStorage &store)=0;

  /// \brief Build the constant pool
  ///
  /// Some processor models (Java byte-code) need a database of constants.
  /// The database is always built, but may remain empty.
  /// \param store may hold configuration information
  virtual void buildConstantPool(DocumentStorage &store)=0;

  virtual void buildInstructions(DocumentStorage &store);	///< Register the p-code operations
  virtual void buildAction(DocumentStorage &store);		///< Build the Action framework

  /// \brief Build the Context database
  ///
  /// Build the database which holds status register settings and other
  /// information that can affect disassembly depending on context.
  /// \param store may hold configuration information
  virtual void buildContext(DocumentStorage &store)=0;

  /// \brief Build any symbols from spec files
  ///
  /// Formal symbols described in a spec file are added to the global scope.
  /// \param store may hold symbol elements
  virtual void buildSymbols(DocumentStorage &store)=0;

  /// \brief Load any relevant specification files
  ///
  /// Processor/architecture specific configuration files are loaded into the XML store
  /// \param store is the document store that will hold the configuration
  virtual void buildSpecFile(DocumentStorage &store)=0;

  /// \brief Modify address spaces as required by \b this Architecture
  ///
  /// If spaces need to be truncated or otherwise changed from processor defaults,
  /// this routine performs the modification.
  /// \param trans is the processor disassembly object
  virtual void modifySpaces(Translate *trans)=0;

  virtual void postSpecFile(void);		///< Let components initialize after Translate is built

  virtual void resolveArchitecture(void)=0;	///< Figure out the processor and compiler of the target executable

  void restoreFromSpec(DocumentStorage &store);		///< Fully initialize the Translate object
  void fillinReadOnlyFromLoader(void);			///< Load info about read-only sections
  void initializeSegments();				///< Set up segment resolvers
  void cacheAddrSpaceProperties(void);			///< Calculate some frequently used space properties and cache them
  void createModelAlias(const string &aliasName,const string &parentName);	///< Create name alias for a ProtoModel

  void parseProcessorConfig(DocumentStorage &store);	///< Apply processor specific configuration
  void parseCompilerConfig(DocumentStorage &store);	///< Apply compiler specific configuration
  void parseExtraRules(DocumentStorage &store);		///< Apply any Rule tags

  void decodeDynamicRule(Decoder &decoder);		///< Apply details of a dynamic Rule object
  ProtoModel *decodeProto(Decoder &decoder);		///< Parse a proto-type model from a stream
  void decodeProtoEval(Decoder &decoder);		///< Apply prototype evaluation configuration
  void decodeDefaultProto(Decoder &decoder);		///< Apply default prototype model configuration
  void decodeGlobal(Decoder &decoder,vector<RangeProperties> &rangeProps);	///< Parse information about global ranges
  void addToGlobalScope(const RangeProperties &props);	///< Add a memory range to the set of addresses considered \e global
  void addOtherSpace(void);                         	///< Add OTHER space and all of its overlays to the symboltab
  void decodeReadOnly(Decoder &decoder);		///< Apply read-only region configuration
  void decodeVolatile(Decoder &decoder);		///< Apply volatile region configuration
  void decodeReturnAddress(Decoder &decoder);		///< Apply return address configuration
  void decodeIncidentalCopy(Decoder &decoder);		///< Apply incidental copy configuration
  void decodeRegisterData(Decoder &decoder);		///< Read specific register properties
  void decodeStackPointer(Decoder &decoder);		///< Apply stack pointer configuration
  void decodeDeadcodeDelay(Decoder &decoder);		///< Apply dead-code delay configuration
  void decodeInferPtrBounds(Decoder &decoder);		///< Apply pointer inference bounds
  void decodeFuncPtrAlign(Decoder &decoder);		///< Apply function pointer alignment configuration
  void decodeSpacebase(Decoder &decoder);		///< Create an additional indexed space
  void decodeNoHighPtr(Decoder &decoder);		///< Apply memory alias configuration
  void decodePreferSplit(Decoder &decoder);		///< Designate registers to be split
  void decodeAggressiveTrim(Decoder &decoder);		///< Designate how to trim extension p-code ops
};

/// \brief A resolver for segmented architectures
///
/// When the decompiler is attempting to resolve embedded constants as pointers,
/// this class tries to recover segment info for near pointers by looking up
/// tracked registers in context
class SegmentedResolver : public AddressResolver {
  Architecture *glb;		///< The architecture owning the segmented space
  AddrSpace *spc;		///< The address space being segmented
  SegmentOp *segop;		///< The segment operator
public:
  /// Construct a segmented resolver
  /// \param g is the owning Architecture
  /// \param sp is the segmented space
  /// \param sop is the segment operator
  SegmentedResolver(Architecture *g,AddrSpace *sp,SegmentOp *sop) { glb=g; spc=sp; segop=sop; }
  virtual Address resolve(uintb val,int4 sz,const Address &point,uintb &fullEncoding);
};

/// The Translate object keeps track of address ranges for which
/// it is effectively impossible to have a pointer into. This is
/// used for pointer aliasing calculations.  This routine returns
/// \b true if it is \e possible to have pointers into the indicated
/// range.
/// \param loc is the starting address of the range
/// \param size is the size of the range in bytes
/// \return \b true if pointers are possible
inline bool Architecture::highPtrPossible(const Address &loc,int4 size) const {
  if (loc.getSpace()->getType() == IPTR_INTERNAL) return false;
  return !nohighptr.inRange(loc,size);
}

} // End namespace ghidra
#endif
