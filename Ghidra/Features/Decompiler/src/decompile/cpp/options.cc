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
#include "options.hh"
#include "funcdata.hh"
#include "flow.hh"
#include "printc.hh"

/// If the parameter is "on" return \b true, if "off" return \b false.
/// Any other value causes an exception.
/// \param p is the parameter
/// \return the parsed boolean value
bool ArchOption::onOrOff(const string &p)

{
  if (p.size()==0)
    return true;
  if (p == "on")
    return true;
  if (p == "off")
    return false;
  throw ParseError("Must specify toggle value, on/off");
}

/// To facilitate command parsing, enter the new ArchOption instance into
/// the map based on its name
/// \param option is the new ArchOption instance
void OptionDatabase::registerOption(ArchOption *option)

{
  optionmap[option->getName()] = option;
}

/// Register all possible ArchOption objects with this database and set-up the parsing map.
/// \param g is the Architecture owning \b this database
OptionDatabase::OptionDatabase(Architecture *g)

{
  glb = g;
  registerOption(new OptionExtraPop());
  registerOption(new OptionReadOnly());
  registerOption(new OptionIgnoreUnimplemented());
  registerOption(new OptionErrorUnimplemented());
  registerOption(new OptionErrorReinterpreted());
  registerOption(new OptionErrorTooManyInstructions());
  registerOption(new OptionDefaultPrototype());
  registerOption(new OptionInferConstPtr());
  registerOption(new OptionForLoops());
  registerOption(new OptionInline());
  registerOption(new OptionNoReturn());
  registerOption(new OptionStructAlign());
  registerOption(new OptionProtoEval());
  registerOption(new OptionWarning());
  registerOption(new OptionNullPrinting());
  registerOption(new OptionInPlaceOps());
  registerOption(new OptionConventionPrinting());
  registerOption(new OptionNoCastPrinting());
  registerOption(new OptionMaxLineWidth());
  registerOption(new OptionIndentIncrement());
  registerOption(new OptionCommentIndent());
  registerOption(new OptionCommentStyle());
  registerOption(new OptionCommentHeader());
  registerOption(new OptionCommentInstruction());
  registerOption(new OptionIntegerFormat());
  registerOption(new OptionCurrentAction());
  registerOption(new OptionAllowContextSet());
  registerOption(new OptionSetAction());
  registerOption(new OptionSetLanguage());
  registerOption(new OptionJumpLoad());
  registerOption(new OptionToggleRule());
  registerOption(new OptionAliasBlock());
  registerOption(new OptionMaxInstruction());
  registerOption(new OptionNamespaceStrategy());
}

OptionDatabase::~OptionDatabase(void)

{
  map<string,ArchOption *>::iterator iter;
  for(iter=optionmap.begin();iter!=optionmap.end();++iter)
    delete (*iter).second;
}

/// Perform an \e option \e command directly, given its name and optional parameters
/// \param nm is the registered name of the option
/// \param p1 is the first optional parameter
/// \param p2 is the second optional parameter
/// \param p3 is the third optional parameter
/// \return the confirmation/failure method after trying to apply the option
string OptionDatabase::set(const string &nm,const string &p1,const string &p2,const string &p3)

{
  map<string,ArchOption *>::const_iterator iter;
  iter = optionmap.find(nm);
  if (iter == optionmap.end())
    throw ParseError("Unknown option: "+nm);
  ArchOption *opt = (*iter).second;
  return opt->apply(glb,p1,p2,p3);
}

/// Unwrap the name and optional parameters and call method set()
/// \param el is the command XML tag
void OptionDatabase::parseOne(const Element *el)

{
  const string &optname( el->getName() );
  const List &list(el->getChildren());
  List::const_iterator iter;
  
  string p1,p2,p3;

  iter = list.begin();
  if (iter != list.end()) {
    p1 = (*iter)->getContent();
    ++iter;
    if (iter != list.end()) {
      p2 = (*iter)->getContent();
      ++iter;
      if (iter != list.end()) {
	p3 = (*iter)->getContent();
	++iter;
	if (iter != list.end())
	  throw LowlevelError("Too many parameters to option: "+optname);
      }
    }
  }
  else
    p1 = el->getContent();	// If no children, content is param 1
  set(optname,p1,p2,p3);
}

/// Parse the \<optionslist> tag, treating each sub-tag as an \e option \e command.
/// \param el is the \<optionslist> tag
void OptionDatabase::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter)
    parseOne(*iter);
}

/// \class OptionExtraPop
/// \brief Set the \b extrapop parameter used by the (default) prototype model.
///
/// The \b extrapop for a function is the number of bytes popped from the stack that
/// a calling function can assume when this function is called.
///
/// The first parameter is the integer value to use as the \e extrapop, or the special
/// value "unknown" which triggers the \e extrapop recovery analysis.
///
/// The second parameter, if present, indicates a specific function to modify. Otherwise,
/// the default prototype model is modified.
string OptionExtraPop::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  int4 expop = -300;
  string res;
  if (p1 == "unknown")
    expop = ProtoModel::extrapop_unknown;
  else {
    istringstream s1(p1);
    s1.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
    s1 >> expop;
  }
  if (expop == -300)
    throw ParseError("Bad extrapop adjustment parameter");
  if (p2.size() != 0) {
    Funcdata *fd;
    fd = glb->symboltab->getGlobalScope()->queryFunction( p2 );
    if (fd == (Funcdata *)0)
      throw RecovError("Unknown function name: "+p2);
    fd->getFuncProto().setExtraPop(expop);
    res = "ExtraPop set for function "+p2;
  }
  else {
    glb->defaultfp->setExtraPop(expop);
    if (glb->evalfp_current != (ProtoModel *)0)
      glb->evalfp_current->setExtraPop(expop);
    if (glb->evalfp_called != (ProtoModel *)0)
      glb->evalfp_called->setExtraPop(expop);
    res = "Global extrapop set";
  }
  return res;
}

/// \class OptionReadOnly
/// \brief Toggle whether read-only memory locations have their value propagated
///
/// Setting this to "on", causes the decompiler to treat read-only memory locations as
/// constants that can be propagated.
string OptionReadOnly::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size()==0)
    throw ParseError("Read-only option must be set \"on\" or \"off\"");
  glb->readonlypropagate = onOrOff(p1);
  if (glb->readonlypropagate)
    return "Read-only memory locations now propagate as constants";
  return "Read-only memory locations now do not propagate";
}

/// \class OptionDefaultPrototype
/// \brief Set the default prototype model for analyzing unknown functions
///
/// The first parameter must give the name of a registered prototype model.
string OptionDefaultPrototype::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  glb->setDefaultModel(p1);
  return "Set default prototype to "+p1;
}

/// \class OptionInferConstPtr
/// \brief Toggle whether the decompiler attempts to infer constant pointers
///
/// Setting the first parameter to "on" causes the decompiler to check if unknown
/// constants look like a reference to a known symbol's location.
string OptionInferConstPtr::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Constant pointers are now inferred";
    glb->infer_pointers = true;
  }
  else {
    res = "Constant pointers must now be set explicitly";
    glb->infer_pointers = false;
  }
  return res;
}

/// \class OptionForLoops
/// \brief Toggle whether the decompiler attempts to recover \e for-loop variables
///
/// Setting the first parameter to "on" causes the decompiler to search for a suitable loop variable
/// controlling iteration of a \e while-do block.  The \e for-loop displays the following on a single line:
///    - loop variable initializer (optional)
///    - loop condition
///    - loop variable incrementer
///
string OptionForLoops::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  glb->analyze_for_loops = onOrOff(p1);

  string res = "Recovery of for-loops is " + p1;
  return res;
}

/// \class OptionInline
/// \brief Mark/unmark a specific function as \e inline
///
/// The first parameter gives the symbol name of a function. The second parameter is
/// true" to set the \e inline property, "false" to clear.
string OptionInline::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  Funcdata *infd = glb->symboltab->getGlobalScope()->queryFunction( p1 );
  if (infd == (Funcdata *)0)
    throw RecovError("Unknown function name: "+p1);
  bool val;
  if (p2.size()==0)
    val = true;
  else
    val = (p2 == "true");
  infd->getFuncProto().setInline(val);
  string prop;
  if (val)
    prop = "true";
  else
    prop = "false";
  string res = "Inline property for function "+p1+" = "+prop;
  return res;
}

/// \class OptionNoReturn
/// \brief Mark/unmark a specific function with the \e noreturn property
///
/// The first parameter is the symbol name of the function. The second parameter
/// is "true" to enable the \e noreturn property, "false" to disable.
string OptionNoReturn::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  Funcdata *infd = glb->symboltab->getGlobalScope()->queryFunction( p1 );
  if (infd == (Funcdata *)0)
    throw RecovError("Unknown function name: "+p1);
  bool val;
  if (p2.size()==0)
    val = true;
  else
    val = (p2 == "true");
  infd->getFuncProto().setNoReturn(val);
  string prop;
  if (val)
    prop = "true";
  else
    prop = "false";
  string res = "No return property for function "+p1+" = "+prop;
  return res;
}

/// \class OptionStructAlign
/// \brief Alter the "structure alignment" data organization setting
///
/// The first parameter must an integer value indicating the desired alignment
string OptionStructAlign::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  int4 val  = -1;
  istringstream s(p1);
  s >> dec >> val;
  if (val == -1)
    throw ParseError("Missing alignment value");

  glb->types->setStructAlign(val);
  return "Structure alignment set";
}

/// \class OptionWarning
/// \brief Toggle whether a warning should be issued if a specific action/rule is applied.
///
/// The first parameter gives the name of the Action or RuleAction.  The second parameter
/// is "on" to turn on warnings, "off" to turn them off.
string OptionWarning::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size()==0)
    throw ParseError("No action/rule specified");
  bool val;
  if (p2.size()==0)
    val = true;
  else
    val = onOrOff(p2);
  bool res = glb->allacts.getCurrent()->setWarning(val,p1);
  if (!res)
    throw RecovError("Bad action/rule specifier: "+p1);
  string prop;
  prop = val ? "on" : "off";
  return "Warnings for "+p1+" turned "+prop;
}

/// \class OptionNullPrinting
/// \brief Toggle whether null pointers should be printed as the string "NULL"
string OptionNullPrinting::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  if (glb->print->getName() != "c-language")
    return "Only c-language accepts the null printing option";
  PrintC *lng = (PrintC *)glb->print;
  lng->setNULLPrinting(val);
  string prop;
  prop = val ? "on" : "off";
  return "Null printing turned "+prop;
}

/// \class OptionInPlaceOps
/// \brief Toggle whether \e in-place operators (+=, *=, &=, etc.) are emitted by the decompiler
string OptionInPlaceOps::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  if (glb->print->getName() != "c-language")
    return "Can only set inplace operators for C language";
  PrintC *lng = (PrintC *)glb->print;
  lng->setInplaceOps(val);
  string prop;
  prop = val ? "on" : "off";
  return "Inplace operators turned "+prop;
}

/// \class OptionConventionPrinting
/// \brief Toggle whether the \e calling \e convention is printed when emitting function prototypes
string OptionConventionPrinting::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  if (glb->print->getName() != "c-language")
    return "Can only set convention printing for C language";
  PrintC *lng = (PrintC *)glb->print;
  lng->setConvention(val);
  string prop;
  prop = val ? "on" : "off";
  return "Convention printing turned "+prop;
}

/// \class OptionNoCastPrinting
/// \brief Toggle whether \e cast syntax is emitted by the decompiler or stripped
string OptionNoCastPrinting::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  PrintC *lng = dynamic_cast<PrintC *>(glb->print);
  if (lng == (PrintC *)0)
    return "Can only set no cast printing for C language";
  lng->setNoCastPrinting(val);
  string prop;
  prop = val ? "on" : "off";
  return "No cast printing turned "+prop;
}

/// \class OptionHideExtensions
/// \brief Toggle whether implied extensions (ZEXT or SEXT) are printed
string OptionHideExtensions::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  PrintC *lng = dynamic_cast<PrintC *>(glb->print);
  if (lng == (PrintC *)0)
    return "Can only toggle extension hiding for C language";
  lng->setHideImpliedExts(val);
  string prop;
  prop = val ? "on" : "off";
  return "Implied extension hiding turned "+prop;
}

/// \class OptionMaxLineWidth
/// \brief Set the maximum number of characters per decompiled line
///
/// The first parameter is an integer value passed to the pretty printer as the maximum
/// number of characters to emit in a single line before wrapping.
string OptionMaxLineWidth::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  istringstream s(p1);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  int4 val = -1;
  s >> val;
  if (val==-1)
    throw ParseError("Must specify integer linewidth");
  glb->print->setMaxLineSize(val);
  return "Maximum line width set to "+p1;
}

/// \class OptionIndentIncrement
/// \brief Set the number of characters to indent per nested scope.
///
/// The first parameter is the integer value specifying how many characters to indent.
string OptionIndentIncrement::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  istringstream s(p1);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  int4 val = -1;
  s >> val;
  if (val==-1)
    throw ParseError("Must specify integer increment");
  glb->print->setIndentIncrement(val);
  return "Characters per indent level set to "+p1;
}

/// \class OptionCommentIndent
/// \brief How many characters to indent comment lines.
///
/// The first parameter gives the integer value.  Comment lines are indented this much independent
/// of the associated code's nesting depth.
string OptionCommentIndent::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  istringstream s(p1);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  int4 val = -1;
  s >> val;
  if (val==-1)
    throw ParseError("Must specify integer comment indent");
  glb->print->setLineCommentIndent(val);
  return "Comment indent set to "+p1;
}

/// \class OptionCommentStyle
/// \brief Set the style of comment emitted by the decompiler
///
/// The first parameter is either "c", "cplusplus", a string starting with "/*", or a string starting with "//"
string OptionCommentStyle::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  glb->print->setCommentStyle(p1);
  return "Comment style set to "+p1;
}

/// \class OptionCommentHeader
/// \brief Toggle whether different comment \e types are emitted by the decompiler in the header for a function
///
/// The first parameter specifies the comment type: "header" and "warningheader"
/// The second parameter is the toggle value "on" or "off".
string OptionCommentHeader::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool toggle = onOrOff(p2);
  uint4 flags = glb->print->getHeaderComment();
  uint4 val = Comment::encodeCommentType(p1);
  if (toggle)
    flags |= val;
  else
    flags &= ~val;
  glb->print->setHeaderComment(flags);
  string prop;
  prop = toggle ? "on" : "off";
  return "Header comment type "+p1+" turned "+prop;
}

/// \class OptionCommentInstruction
/// \brief Toggle whether different comment \e types are emitted by the decompiler in the body of a function
///
/// The first parameter specifies the comment type: "warning", "user1", "user2", etc.
/// The second parameter is the toggle value "on" or "off".
string OptionCommentInstruction::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool toggle = onOrOff(p2);
  uint4 flags = glb->print->getInstructionComment();
  uint4 val = Comment::encodeCommentType(p1);
  if (toggle)
    flags |= val;
  else
    flags &= ~val;
  glb->print->setInstructionComment(flags);
  string prop;
  prop = toggle ? "on" : "off";
  return "Instruction comment type "+p1+" turned "+prop;
}

/// \class OptionIntegerFormat
/// \brief Set the formatting strategy used by the decompiler to emit integers
///
/// The first parameter is the strategy name: "hex", "dec", or "best"
string OptionIntegerFormat::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  glb->print->setIntegerFormat(p1);
  return "Integer format set to "+p1;
}

/// \class OptionSetAction
/// \brief Establish a new root Action for the decompiler
///
/// The first parameter specifies the name of the root Action. If a second parameter
/// is given, it specifies the name of a new root Action, which  is created by copying the
/// Action specified with the first parameter.  In this case, the current root Action is
/// set to the new copy, which can then by modified
string OptionSetAction::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size()==0)
    throw ParseError("Must specify preexisting action");

  if (p2.size() != 0) {
    glb->allacts.cloneGroup(p1,p2);
    glb->allacts.setCurrent(p2);
    return "Created "+p2+" by cloning "+p1+" and made it current";
  }
  glb->allacts.setCurrent(p1);
  return "Set current action to "+p1;
}

/// \class OptionCurrentAction
/// \brief Toggle a sub-group of actions within a root Action
///
/// If two parameters are given, the first indicates the name of the sub-group, and the second is
/// the toggle value, "on" or "off". The change is applied to the current root Action.
///
/// If three parameters are given, the first indicates the root Action (which will be set as current)
/// to modify. The second and third parameters give the name of the sub-group and the toggle value.
string OptionCurrentAction::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if ((p1.size()==0)||(p2.size()==0))
    throw ParseError("Must specify subaction, on/off");
  bool val;
  string res = "Toggled ";

  if (p3.size() != 0) {
    glb->allacts.setCurrent(p1);
    val = onOrOff(p3);
    glb->allacts.toggleAction(p1,p2,val);
    res += p2 + " in action "+p1;
  }
  else {
    val = onOrOff(p2);
    glb->allacts.toggleAction(glb->allacts.getCurrentName(),p1,val);
    res += p1 + " in action "+glb->allacts.getCurrentName();
  }

  return res;
}

/// \class OptionAllowContextSet
/// \brief Toggle whether the disassembly engine is allowed to modify context
///
/// If the first parameter is "on", disassembly can make changes to context
string OptionAllowContextSet::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string prop = val ? "on" : "off";
  string res = "Toggled allowcontextset to "+prop;
  glb->translate->allowContextSet(val);

  return res;
}

/// \class OptionIgnoreUnimplemented
/// \brief Toggle whether unimplemented instructions are treated as a \e no-operation
///
/// If the first parameter is "on", unimplemented instructions are ignored, otherwise
/// they are treated as an artificial \e halt in the control flow.
string OptionIgnoreUnimplemented::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Unimplemented instructions are now ignored (treated as nop)";
    glb->flowoptions |= FlowInfo::ignore_unimplemented;
  }
  else {
    res = "Unimplemented instructions now generate warnings";
    glb->flowoptions &= ~((uint4)FlowInfo::ignore_unimplemented);
  }

  return res;
}

/// \class OptionErrorUnimplemented
/// \brief Toggle whether unimplemented  instructions are treated as a fatal error.
///
/// If the first parameter is "on", decompilation of functions with unimplemented instructions
/// will terminate with a fatal error message. Otherwise, warning comments will be generated.
string OptionErrorUnimplemented::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Unimplemented instructions are now a fatal error";
    glb->flowoptions |= FlowInfo::error_unimplemented;
  }
  else {
    res = "Unimplemented instructions now NOT a fatal error";
    glb->flowoptions &= ~((uint4)FlowInfo::error_unimplemented);
  }

  return res;
}

/// \class OptionErrorReinterpreted
/// \brief Toggle whether off-cut reinterpretation of an instruction is a fatal error
///
/// If the first parameter is "on", interpreting the same code bytes at two or more different
/// \e cuts, during disassembly, is considered a fatal error.
string OptionErrorReinterpreted::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Instruction reinterpretation is now a fatal error";
    glb->flowoptions |= FlowInfo::error_reinterpreted;
  }
  else {
    res = "Instruction reinterpretation is now NOT a fatal error";
    glb->flowoptions &= ~((uint4)FlowInfo::error_reinterpreted);
  }

  return res;
}
/// \class OptionErrorTooManyInstructions
/// \brief Toggle whether too many instructions in one function body is considered a fatal error.
///
/// If the first parameter is "on" and the number of instructions in a single function body exceeds
/// the threshold, then decompilation will halt for that function with a fatal error. Otherwise,
/// artificial halts are generated to prevent control-flow into further instructions.
string OptionErrorTooManyInstructions::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Too many instructions are now a fatal error";
    glb->flowoptions |= FlowInfo::error_toomanyinstructions;
  }
  else {
    res = "Too many instructions are now NOT a fatal error";
    glb->flowoptions &= ~((uint4)FlowInfo::error_toomanyinstructions);
  }

  return res;
}

/// \class OptionProtoEval
/// \brief Set the prototype model to use when evaluating the parameters of the \e current function
///
/// The first parameter gives the name of the prototype model. The string "default" can be given
/// to refer to the format \e default model for the architecture. The specified model is used to
/// evaluate parameters of the function actively being decompiled, which may be distinct from the
/// model used to evaluate sub-functions.
string OptionProtoEval::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  ProtoModel *model = (ProtoModel *)0;
  
  if (p1.size()==0)
    throw ParseError("Must specify prototype model");

  if (p1 == "default")
    model = glb->defaultfp;
  else {
    model = glb->protoModels[p1];
    if (model == (ProtoModel *)0)
      throw ParseError("Unknown prototype model: "+p1);
  }
  string res = "Set current evaluation to " + p1;
  glb->evalfp_current = model;
  return res;
}

/// \class OptionSetLanguage
/// \brief Set the current language emitted by the decompiler
///
/// The first specifies the name of the language to emit: "c-language", "java-language", etc.
string OptionSetLanguage::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  string res;

  glb->setPrintLanguage(p1);
  res = "Decompiler produces "+p1;
  return res;
}

/// \class OptionJumpLoad
/// \brief Toggle whether the decompiler should try to recover the table used to evaluate a switch
///
/// If the first parameter is "on", the decompiler will record the memory locations with constant values
/// that were accessed as part of the jump-table so that they can be formally labeled.
string OptionJumpLoad::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Jumptable analysis will record loads required to calculate jump address";
    glb->flowoptions |= FlowInfo::record_jumploads;
  }
  else {
    res = "Jumptable analysis will NOT record loads";
    glb->flowoptions &= ~((uint4)FlowInfo::record_jumploads);
  }
  return res;
}

/// \class OptionToggleRule
/// \brief Toggle whether a specific Rule is applied in the current Action
///
/// The first parameter must be a name \e path describing the unique Rule instance
/// to be toggled.  The second parameter is "on" to \e enable the Rule, "off" to \e disable.
string OptionToggleRule::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size() == 0)
    throw ParseError("Must specify rule path");
  if (p2.size() == 0)
    throw ParseError("Must specify on/off");
  bool val = onOrOff(p2);

  Action *root = glb->allacts.getCurrent();
  if (root == (Action *)0)
    throw LowlevelError("Missing current action");
  string res;
  if (!val) {
    if (root->disableRule(p1))
      res = "Successfully disabled";
    else
      res = "Failed to disable";
    res += " rule";
  }
  else {
    if (root->enableRule(p1))
      res = "Successfully enabled";
    else
      res = "Failed to enable";
    res += " rule";
  }
  return res;
}

/// \class OptionAliasBlock
/// \brief Set how locked data-types on the stack affect alias heuristics
///
/// Stack analysis uses the following simple heuristic: a pointer is unlikely to reference (alias)
/// a stack location if there is a locked data-type between the pointer base and the location.
/// This option determines what kind of locked data-types \b block aliases in this way.
///   - none - no data-types will block an alias
///   - struct - only structure data-types will block an alias
///   - array - array data-types (and structure data-types) will block an alias
///   - all - all locked data-types will block an alias
string OptionAliasBlock::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size() == 0)
    throw ParseError("Must specify alias block level");
  int4 oldVal = glb->alias_block_level;
  if (p1 == "none")
    glb->alias_block_level = 0;
  else if (p1 == "struct")
    glb->alias_block_level = 1;
  else if (p1 == "array")
    glb->alias_block_level = 2;		// The default. Let structs and arrays block aliases
  else if (p1 == "all")
    glb->alias_block_level = 3;
  else
    throw ParseError("Unknown alias block level: "+p1);
  if (oldVal == glb->alias_block_level)
    return "Alias block level unchanged";
  return "Alias block level set to " + p1;
}

/// \class OptionMaxInstruction
/// \brief Maximum number of instructions that can be processed in a single function
///
/// The first parameter is an integer specifying the maximum.
string OptionMaxInstruction::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size() == 0)
    throw ParseError("Must specify number of instructions");

  int4 newMax = -1;
  istringstream s1(p1);
  s1.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
  s1 >> newMax;
  if (newMax < 0)
    throw ParseError("Bad maxinstruction parameter");
  glb->max_instructions = newMax;
  return "Maximum instructions per function set";
}

/// \class OptionNamespaceStrategy
/// \brief How should namespace tokens be displayed
///
/// The first parameter gives the strategy identifier, mapping to PrintLanguage::namespace_strategy.
string OptionNamespaceStrategy::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  PrintLanguage::namespace_strategy strategy;
  if (p1 == "minimal")
    strategy = PrintLanguage::MINIMAL_NAMESPACES;
  else if (p1 == "all")
    strategy = PrintLanguage::ALL_NAMESPACES;
  else if (p1 == "none")
    strategy = PrintLanguage::NO_NAMESPACES;
  else
    throw ParseError("Must specify a valid strategy");
  glb->print->setNamespaceStrategy(strategy);
  return "Namespace strategy set";
}
