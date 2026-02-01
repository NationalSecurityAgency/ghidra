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
/// \file options.hh
/// \brief Classes for processing architecture configuration options

#ifndef __OPTIONS_HH__
#define __OPTIONS_HH__

#include "error.hh"
#include "marshal.hh"

namespace ghidra {

class Architecture;

extern ElementId ELEM_ALIASBLOCK;		///< Marshaling element \<aliasblock>
extern ElementId ELEM_ALLOWCONTEXTSET;		///< Marshaling element \<allowcontextset>
extern ElementId ELEM_ANALYZEFORLOOPS;		///< Marshaling element \<analyzeforloops>
extern ElementId ELEM_COMMENTHEADER;		///< Marshaling element \<commentheader>
extern ElementId ELEM_COMMENTINDENT;		///< Marshaling element \<commentindent>
extern ElementId ELEM_COMMENTINSTRUCTION;	///< Marshaling element \<commentinstruction>
extern ElementId ELEM_COMMENTSTYLE;		///< Marshaling element \<commentstyle>
extern ElementId ELEM_CONVENTIONPRINTING;	///< Marshaling element \<conventionprinting>
extern ElementId ELEM_CURRENTACTION;		///< Marshaling element \<currentaction>
extern ElementId ELEM_DEFAULTPROTOTYPE;		///< Marshaling element \<defaultprototype>
extern ElementId ELEM_ERRORREINTERPRETED;	///< Marshaling element \<errorreinterpreted>
extern ElementId ELEM_ERRORTOOMANYINSTRUCTIONS;	///< Marshaling element \<errortoomanyinstructions>
extern ElementId ELEM_ERRORUNIMPLEMENTED;	///< Marshaling element \<errorunimplemented>
extern ElementId ELEM_EXTRAPOP;			///< Marshaling element \<extrapop>
extern ElementId ELEM_IGNOREUNIMPLEMENTED;	///< Marshaling element \<ignoreunimplemented>
extern ElementId ELEM_INDENTINCREMENT;		///< Marshaling element \<indentincrement>
extern ElementId ELEM_INFERCONSTPTR;		///< Marshaling element \<inferconstptr>
extern ElementId ELEM_INLINE;			///< Marshaling element \<inline>
extern ElementId ELEM_INPLACEOPS;		///< Marshaling element \<inplaceops>
extern ElementId ELEM_INTEGERFORMAT;		///< Marshaling element \<integerformat>
extern ElementId ELEM_JUMPLOAD;			///< Marshaling element \<jumpload>
extern ElementId ELEM_MAXINSTRUCTION;		///< Marshaling element \<maxinstruction>
extern ElementId ELEM_MAXLINEWIDTH;		///< Marshaling element \<maxlinewidth>
extern ElementId ELEM_NAMESPACESTRATEGY;	///< Marshaling element \<namespacestrategy>
extern ElementId ELEM_NOCASTPRINTING;		///< Marshaling element \<nocastprinting>
extern ElementId ELEM_NORETURN;			///< Marshaling element \<noreturn>
extern ElementId ELEM_NULLPRINTING;		///< Marshaling element \<nullprinting>
extern ElementId ELEM_OPTIONSLIST;		///< Marshaling element \<optionslist>
extern ElementId ELEM_PARAM1;			///< Marshaling element \<param1>
extern ElementId ELEM_PARAM2;			///< Marshaling element \<param2>
extern ElementId ELEM_PARAM3;			///< Marshaling element \<param3>
extern ElementId ELEM_PROTOEVAL;		///< Marshaling element \<protoeval>
extern ElementId ELEM_SETACTION;		///< Marshaling element \<setaction>
extern ElementId ELEM_SETLANGUAGE;		///< Marshaling element \<setlanguage>
extern ElementId ELEM_SPLITDATATYPE;		///< Marshaling element \<splitdatatype>
extern ElementId ELEM_STRUCTALIGN;		///< Marshaling element \<structalign>
extern ElementId ELEM_TOGGLERULE;		///< Marshaling element \<togglerule>
extern ElementId ELEM_WARNING;			///< Marshaling element \<warning>
extern ElementId ELEM_JUMPTABLEMAX;		///< Marshaling element \<jumptablemax>
extern ElementId ELEM_NANIGNORE;		///< Marshaling element \<nanignore>

/// \brief Base class for options classes that affect the configuration of the Architecture object
///
/// Each class instance affects configuration through its apply() method, which is handed the
/// Architecture object to be configured along with string based parameters. The apply() methods
/// are run once during initialization of the Architecture object.
class ArchOption {
protected:
  string name;		///< Name of the option
public:
  string getName(void) const { return name; }	///< Return the name of the option

  /// \brief Apply a particular configuration option to the Architecture
  ///
  /// This method is overloaded by the different Option classes to provide possible configuration
  /// of different parts of the Architecture. The user can provide up to three optional parameters
  /// to tailor a specific type of configuration. The method returns a confirmation/failure message
  /// as feedback.
  /// \param glb is the Architecture being configured
  /// \param p1 is the first optional configuration string
  /// \param p2 is the second optional configuration string
  /// \param p3 is the third optional configuration string
  /// \return a confirmation/failure message
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const=0;
  virtual ~ArchOption(void) {}
  static bool onOrOff(const string &p);	///< Parse an "on" or "off" string
};

/// \brief A Dispatcher for possible ArchOption commands
///
/// An \b option \b command is a specific request by a user to change the configuration options
/// for an Architecture.  This class takes care of dispatching the command to the proper ArchOption
/// derived class, which does the work of actually modifying the configuration. The command is issued
/// either through the set() method directly, or via an element handed to the decode() method.
/// The decode() method expects an \<optionslist> element with one or more children. The child names
/// match the registered name of the option and have up to three child elements, \<param1>, \<param2> and \<param3>,
/// whose content is provided as the optional parameters to command.
class OptionDatabase {
  Architecture *glb;				///< The Architecture affected by the contained ArchOption
  map<uint4,ArchOption *> optionmap;		///< A map from option id to registered ArchOption instance
  void registerOption(ArchOption *option);	///< Map from ArchOption name to its class instance
public:
  OptionDatabase(Architecture *g);		///< Construct given the owning Architecture
  ~OptionDatabase(void);			///< Destructor
  string set(uint4 nameId,const string &p1="",const string &p2="",const string &p3="");	///< Issue an option command
  void decodeOne(Decoder &decoder);		///< Parse and execute a single option element
  void decode(Decoder &decoder);		///< Execute a series of \e option \e commands parsed from a stream
};  

class OptionExtraPop : public ArchOption {
public:
  OptionExtraPop(void) { name = "extrapop"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionReadOnly : public ArchOption {
public:
  OptionReadOnly(void) { name = "readonly"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionDefaultPrototype : public ArchOption {
public:
  OptionDefaultPrototype(void) { name = "defaultprototype"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionInferConstPtr : public ArchOption {
public:
  OptionInferConstPtr(void) { name = "inferconstptr"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionForLoops : public ArchOption {
public:
  OptionForLoops(void) { name = "analyzeforloops"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionInline : public ArchOption {
public:
  OptionInline(void) { name = "inline"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionNoReturn : public ArchOption {
public:
  OptionNoReturn(void) { name = "noreturn"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionWarning : public ArchOption {
public:
  OptionWarning(void) { name = "warning"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionNullPrinting : public ArchOption {
public:
  OptionNullPrinting(void) { name = "nullprinting"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionInPlaceOps : public ArchOption {
public:
  OptionInPlaceOps(void) { name = "inplaceops"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionConventionPrinting : public ArchOption {
public:
  OptionConventionPrinting(void) { name = "conventionprinting"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionNoCastPrinting : public ArchOption {
public:
  OptionNoCastPrinting(void) { name = "nocastprinting"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionHideExtensions : public ArchOption {
public:
  OptionHideExtensions(void) { name="hideextensions"; }		///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionMaxLineWidth : public ArchOption {
public:
  OptionMaxLineWidth(void) { name = "maxlinewidth"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionIndentIncrement : public ArchOption {
public:
  OptionIndentIncrement(void) { name = "indentincrement"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionCommentIndent : public ArchOption {
public:
  OptionCommentIndent(void) { name = "commentindent"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionCommentStyle : public ArchOption {
public:
  OptionCommentStyle(void) { name = "commentstyle"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionCommentHeader : public ArchOption {
public:
  OptionCommentHeader(void) { name = "commentheader"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionCommentInstruction : public ArchOption {
public:
 OptionCommentInstruction(void) { name = "commentinstruction"; }	///< Constructor
 virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionIntegerFormat : public ArchOption {
public:
  OptionIntegerFormat(void) { name = "integerformat"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionBraceFormat : public ArchOption {
public:
  OptionBraceFormat(void) { name = "braceformat"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionSetAction : public ArchOption {
public:
  OptionSetAction(void) { name = "setaction"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionCurrentAction : public ArchOption {
public:
  OptionCurrentAction(void) { name = "currentaction"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionAllowContextSet : public ArchOption {
public:
  OptionAllowContextSet(void) { name = "allowcontextset"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionIgnoreUnimplemented : public ArchOption {
public:
  OptionIgnoreUnimplemented(void) { name = "ignoreunimplemented"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionErrorUnimplemented : public ArchOption {
public:
  OptionErrorUnimplemented(void) { name = "errorunimplemented"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionErrorReinterpreted : public ArchOption {
public:
  OptionErrorReinterpreted(void) { name = "errorreinterpreted"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionErrorTooManyInstructions : public ArchOption {
public:
  OptionErrorTooManyInstructions(void) { name = "errortoomanyinstructions"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionProtoEval : public ArchOption {
public:
  OptionProtoEval(void) { name = "protoeval"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionSetLanguage : public ArchOption {
public:
  OptionSetLanguage(void) { name = "setlanguage"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionJumpTableMax : public ArchOption {
public:
  OptionJumpTableMax(void) { name = "jumptablemax"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionJumpLoad : public ArchOption {
public:
  OptionJumpLoad(void) { name = "jumpload"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionToggleRule : public ArchOption {
public:
  OptionToggleRule(void) { name = "togglerule"; } ///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionAliasBlock : public ArchOption {
public:
  OptionAliasBlock(void) { name = "aliasblock"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionMaxInstruction : public ArchOption {
public:
  OptionMaxInstruction(void) { name="maxinstruction"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionNamespaceStrategy : public ArchOption {
public:
  OptionNamespaceStrategy(void) { name = "namespacestrategy"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionSplitDatatypes : public ArchOption {
public:
  enum {
    option_struct = 1,		///< Split combined structure fields
    option_array = 2,		///< Split combined array elements
    option_pointer = 4		///< Split combined LOAD and STORE operations
  };
  static uint4 getOptionBit(const string &val);		///< Translate option string to a configuration bit
public:
  OptionSplitDatatypes(void) { name = "splitdatatype"; }	///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

class OptionNanIgnore : public ArchOption {
public:
  OptionNanIgnore(void) { name = "nanignore"; }		///< Constructor
  virtual string apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const;
};

} // End namespace ghidra
#endif
