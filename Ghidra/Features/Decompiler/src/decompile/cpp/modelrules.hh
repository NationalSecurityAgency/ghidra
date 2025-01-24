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
/// \file modelrules.hh
/// \brief Definitions for rules governing mapping of data-type to address for prototype models

#ifndef __MODELRULES_HH__
#define __MODELRULES_HH__

#include "op.hh"

namespace ghidra {

class ParameterPieces;
class ParamListStandard;
class ParamEntry;
class ParamActive;

extern AttributeId ATTRIB_SIZES;	///< Marshaling attribute "sizes"

extern ElementId ELEM_DATATYPE;		///< Marshaling element \<datatype>
extern ElementId ELEM_CONSUME;		///< Marshaling element \<consume>
extern ElementId ELEM_CONSUME_EXTRA;	///< Marshaling element \<consume_extra>
extern ElementId ELEM_CONVERT_TO_PTR;	///< Marshaling element \<convert_to_ptr>
extern ElementId ELEM_GOTO_STACK;	///< Marshaling element \<goto_stack>
extern ElementId ELEM_JOIN;		///< Marshaling element \<join>
extern ElementId ELEM_DATATYPE_AT;	///< Marshaling element \<datatype_at>
extern ElementId ELEM_POSITION;		///< Marshaling element \<position>
extern ElementId ELEM_VARARGS;		///< Marshaling element \<varargs>
extern ElementId ELEM_HIDDEN_RETURN;	///< Marshaling element \<hidden_return>
extern ElementId ELEM_JOIN_PER_PRIMITIVE;	///< Marshaling element \<join_per_primitive>
extern ElementId ELEM_JOIN_DUAL_CLASS;	///< Marshaling element \<join_dual_class>
extern ElementId ELEM_EXTRA_STACK;	///< Marshaling element \<extra_stack>

/// \brief Class for extracting primitive elements of a data-type
///
/// This recursively collects the formal \e primitive data-types of a composite data-type,
/// laying them out with their offsets in an array.  Other boolean properties are collected.
class PrimitiveExtractor {
  enum {
    unknown_element = 1,		///< Contains at least one TYPE_UNKNOWN primitive
    unaligned = 2,			///< At least one primitive is not properly aligned
    extra_space = 4,			///< Data-type contains empty space not attributable to alignment padding
    invalid = 8,			///< Data-type exceeded maximum or contained illegal elements
    union_invalid = 16			///< Unions are treated as an illegal element
  };
public:
  /// \brief A primitive data-type and its offset within the containing data-type
  class Primitive {
  public:
    Datatype *dt;		///< Primitive data-type
    int4 offset;		///< Offset within container
    Primitive(Datatype *d,int4 off) { dt = d; offset = off; }	///< Constructor
  };
private:
  vector<Primitive> primitives;	///< List of extracted primitives
  uint4 flags;			///< Boolean properties of the data-type
  int4 checkOverlap(vector<Primitive> &res,vector<Primitive> &small,int4 point,Primitive &big);
  bool commonRefinement(vector<Primitive> &first,vector<Primitive> &second);
  bool handleUnion(TypeUnion *dt,int4 max,int4 offset);		///< Add primitives representing a union data-type
  bool extract(Datatype *dt,int4 max,int4 offset);	///< Extract list of primitives from given data-type
public:
  PrimitiveExtractor(Datatype *dt,bool unionIllegal,int4 offset,int4 max);	///< Constructor
  int4 size(void) const { return primitives.size(); }	///< Return the number of primitives extracted
  const Primitive &get(int4 i) const { return primitives[i]; }	///< Get a particular primitive
  bool isValid(void) const { return (flags & invalid) == 0; }	///< Return \b true if primitives were successfully extracted
  bool containsUnknown(void) const { return (flags & unknown_element)!=0; }	///< Are there \b unknown elements
  bool isAligned(void) const { return (flags & unaligned)==0; }		///< Are all elements aligned
  bool containsHoles(void) const { return (flags & extra_space)!=0; }	///< Is there empty space that is not padding
};

/// \brief A filter selecting a specific class of data-type
///
/// An instance is configured via the decode() method, then a test of whether
/// a data-type belongs to its class can be performed by calling the filter() method.
class DatatypeFilter {
public:
  virtual ~DatatypeFilter(void) {}		///< Destructor

  /// \brief Make a copy of \b this filter
  ///
  /// \return the newly allocated copy
  virtual DatatypeFilter *clone(void) const=0;

  /// \brief Test whether the given data-type belongs to \b this filter's data-type class
  ///
  /// \param dt is the given data-type to test
  /// \return \b true if the data-type is in the class, \b false otherwise
  virtual bool filter(Datatype *dt) const=0;

  /// \brief Configure details of the data-type class being filtered from the given stream
  ///
  /// \param decoder is the given stream decoder
  virtual void decode(Decoder &decoder)=0;

  static DatatypeFilter *decodeFilter(Decoder &decoder);	///< Instantiate a filter from the given stream
};

/// \brief A base class for data-type filters that tests for either a range or an enumerated list of sizes
///
/// Any filter that inherits from \b this, can use ATTRIB_MINSIZE, ATTRIB_MAXSIZE, or ATTRIB_SIZES
/// to place bounds on the possible sizes of data-types.  The bounds are enforced
/// by calling filterOnSize() within the inheriting classes filter() method.
class SizeRestrictedFilter : public DatatypeFilter {
protected:
  int4 minSize;		///< Minimum size of the data-type in bytes
  int4 maxSize;		///< Maximum size of the data-type in bytes
  set<int4> sizes;	///< An enumerated list of sizes (if not empty)
  void initFromSizeList(const string &str);	///< Initialize filter from enumerated list of sizes
public:
  SizeRestrictedFilter(void) { minSize=0; maxSize=0; }	///< Constructor for use with decode()
  SizeRestrictedFilter(int4 min,int4 max);	///< Constructor
  SizeRestrictedFilter(const SizeRestrictedFilter &op2);	///< Copy constructor
  bool filterOnSize(Datatype *dt) const;		///< Enforce any size bounds on a given data-type
  virtual DatatypeFilter *clone(void) const { return new SizeRestrictedFilter(*this); }
  virtual bool filter(Datatype *dt) const { return filterOnSize(dt); }
  virtual void decode(Decoder &decoder);
};

/// \brief Filter on a single meta data-type
///
/// Filters on TYPE_STRUCT or TYPE_FLOAT etc.  Additional filtering on size of the data-type can be configured.
class MetaTypeFilter : public SizeRestrictedFilter {
protected:
  type_metatype metaType;	///< The meta-type this filter lets through
public:
  MetaTypeFilter(type_metatype meta);	///< Constructor for use with decode()
  MetaTypeFilter(type_metatype meta,int4 min,int4 max);	///< Constructor
  MetaTypeFilter(const MetaTypeFilter &op2);	///< Copy constructor
  virtual DatatypeFilter *clone(void) const { return new MetaTypeFilter(*this); }
  virtual bool filter(Datatype *dt) const;
};

/// \brief Filter on a homogeneous aggregate data-type
///
/// All primitive data-types must be the same.
class HomogeneousAggregate : public SizeRestrictedFilter {
  type_metatype metaType;		///< The expected meta-type
  int4 maxPrimitives;			///< Maximum number of primitives in the aggregate
public:
  HomogeneousAggregate(type_metatype meta);	///< Constructor for use with decode()
  HomogeneousAggregate(type_metatype meta,int4 maxPrim,int4 min,int4 max);	///< Constructor
  HomogeneousAggregate(const HomogeneousAggregate &op2);	///< Copy constructor
  virtual DatatypeFilter *clone(void) const { return new HomogeneousAggregate(*this); }
  virtual bool filter(Datatype *dt) const;
};

/// \brief A filter on some aspect of a specific function prototype
///
/// An instance is configured via the decode() method, then a test of whether
/// a function prototype meets its criteria can be performed by calling its filter() method.
class QualifierFilter {
public:
  virtual ~QualifierFilter(void) {}	///< Destructor

  /// \brief Make a copy of \b this qualifier
  ///
  /// \return the newly allocated copy
  virtual QualifierFilter *clone(void) const=0;

  /// \brief Test whether the given function prototype meets \b this filter's criteria
  ///
  /// \param proto is the high-level description of the function prototype to test
  /// \param pos is the position of a specific output (pos=-1) or input (pos >=0) in context
  /// \return \b true if the prototype meets the criteria, \b false otherwise
  virtual bool filter(const PrototypePieces &proto,int4 pos) const=0;

  /// \brief Configure details of the criteria being filtered from the given stream
  ///
  /// \param decoder is the given stream decoder
  virtual void decode(Decoder &decoder) {}
  static QualifierFilter *decodeFilter(Decoder &decoder);	///< Try to instantiate a qualifier filter
};

/// \brief Logically AND multiple QualifierFilters together into a single filter
///
/// An instances contains some number of other arbitrary filters.  In order for \b this filter to
/// pass, all these contained filters must pass.
class AndFilter : public QualifierFilter {
  vector<QualifierFilter *> subQualifiers;	///< Filters being logically ANDed together
public:
  AndFilter(vector<QualifierFilter *> filters);	///< Construct from array of filters
  virtual ~AndFilter(void);
  virtual QualifierFilter *clone(void) const;
  virtual bool filter(const PrototypePieces &proto,int4 pos) const;
  virtual void decode(Decoder &decoder) {}
};

/// \brief A filter that selects a range of function parameters that are considered optional.
///
/// If the underlying function prototype is considered to take variable arguments, the first
/// n parameters (as determined by PrototypePieces.firstVarArgSlot) are considered non-optional.
///\e  If additional data-types are provided beyond the initial \e n, these are considered optional.
/// By default this filter matches on any parameter in a prototype with variable arguments.
/// Optionally, it can filter on a range of parameters that are specified relative to the
/// first variable argument.
///   - \<varargs first="0"/>   - matches optional arguments but not non-optional ones.
///   - \<varargs first="0" last="0"/>  -  matches the first optional argument.
///   - \<varargs first="-1"/> - matches the last non-optional argument and all optional ones.
class VarargsFilter : public QualifierFilter {
  int4 firstPos;			///< Start of range to match (offset relative to first variable arg)
  int4 lastPos;				///< End of range to match
public:
  VarargsFilter(void) { firstPos = 0x80000000; lastPos = 0x7fffffff; }	///< Constructor for use with decode
  VarargsFilter(int4 first,int4 last) { firstPos = first; lastPos = last; }	///< Constructor
  virtual QualifierFilter *clone(void) const { return new VarargsFilter(firstPos,lastPos); }
  virtual bool filter(const PrototypePieces &proto,int4 pos) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Filter that selects for a particular parameter position
///
/// This matches if the position of the current parameter being assigned, within the data-type
/// list, matches the \b position attribute of \b this filter.
class PositionMatchFilter : public QualifierFilter {
  int4 position;	///< Parameter position being filtered for
public:
  PositionMatchFilter(int4 pos) { position = pos; }	///< Constructor
  virtual QualifierFilter *clone(void) const { return new PositionMatchFilter(position); }
  virtual bool filter(const PrototypePieces &proto,int4 pos) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Check if the function signature has a specific data-type in a specific position
/// This filter does not match against the data-type in the current position
/// being assigned, but against a parameter at a fixed position.
class DatatypeMatchFilter : public QualifierFilter {
  int4 position;		///< The position of the data-type to check
  DatatypeFilter *typeFilter;	///< The data-type that must be at \b position
public:
  DatatypeMatchFilter(void) { position = -1; typeFilter = (DatatypeFilter *)0; }	///< Constructor for use with decode
  virtual ~DatatypeMatchFilter(void);
  virtual QualifierFilter *clone(void) const;
  virtual bool filter(const PrototypePieces &proto,int4 pos) const;
  virtual void decode(Decoder &decoder);
};
/// \brief An action that assigns an Address to a function prototype parameter
///
/// A request for the address of either \e return storage or an input parameter is made
/// through the assignAddress() method, which is given full information about the function prototype.
/// Details about how the action performs is configured through the decode() method.
class AssignAction {
public:
  enum {
    success,			///< Data-type is fully assigned
    fail,			///< Action could not be applied
    no_assignment,		///< Do not assign storage for this parameter
    hiddenret_ptrparam,		///< Hidden return pointer as first input parameter
    hiddenret_specialreg,	///< Hidden return pointer in dedicated input register
    hiddenret_specialreg_void	///< Hidden return pointer, but no normal return
  };
protected:
  const ParamListStandard *resource;	///< Resources to which this action applies
  bool fillinOutputActive;	///< If \b true, fillinOutputMap is active
public:
  AssignAction(const ParamListStandard *res) {resource = res; fillinOutputActive = false; }	///< Constructor

  bool canAffectFillinOutput(void) const { return fillinOutputActive; }	///< Return \b true if fillinOutputMap is active

  virtual ~AssignAction(void) {}

  /// \brief Make a copy of \b this action
  ///
  /// \param newResource is the new resource object that will own the clone
  /// \return the newly allocated copy
  virtual AssignAction *clone(const ParamListStandard *newResource) const=0;

  /// \brief Assign an address and other meta-data for a specific parameter or for return storage in context
  ///
  /// The Address is assigned based on the data-type of the parameter, available register
  /// resources, and other details of the function prototype.  Consumed resources are marked.
  /// This method returns a response code:
  ///   - success            - indicating the Address was successfully assigned
  ///   - fail               - if the Address could not be assigned
  ///   - hiddenret_ptrparam - if an additional \e hidden \e return \e parameter is required
  ///
  /// \param dt is the data-type of the parameter or return value
  /// \param proto is the high-level description of the function prototype
  /// \param pos is the position of the parameter (pos>=0) or return storage (pos=-1)
  /// \param tlist is a data-type factory for (possibly) transforming the data-type
  /// \param status is the resource consumption array
  /// \param res will hold the resulting description of the parameter
  /// \return the response code
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const=0;

  /// \brief Test if \b this action could produce return value storage matching the given set of trials
  ///
  /// If there is a return value data-type that could be assigned storage matching the trials by \b this action,
  /// return \b true.  The trials have their matching ParamEntry and offset already set and are already sorted.
  /// \param active is the given set of trials
  /// \return \b true if the trials could form a valid return value
  virtual bool fillinOutputMap(ParamActive *active) const;

  /// \brief Configure any details of how \b this action should behave from the stream
  ///
  /// \param decoder is the given stream decoder
  virtual void decode(Decoder &decoder)=0;
  static AssignAction *decodeAction(Decoder &decoder,const ParamListStandard *res);
  static AssignAction *decodeSideeffect(Decoder &decoder,const ParamListStandard *res);
};

/// \brief Action assigning a parameter Address from the next available stack location
class GotoStack : public AssignAction {
  const ParamEntry *stackEntry;	///< Parameter Entry corresponding to the stack
  void initializeEntry(void);	///< Find stack entry in resource list
public:
  GotoStack(const ParamListStandard *res,int4 val);	///< Constructor for use with decode
  GotoStack(const ParamListStandard *res);	///< Constructor
  virtual AssignAction *clone(const ParamListStandard *newResource) const { return new GotoStack(newResource); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual bool fillinOutputMap(ParamActive *active) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Action converting the parameter's data-type to a pointer, and assigning storage for the pointer
///
/// This assumes the data-type is stored elsewhere and only the pointer is passed as a parameter
class ConvertToPointer : public AssignAction {
  AddrSpace *space;	///< Address space used for pointer size
public:
  ConvertToPointer(const ParamListStandard *res);	///< Constructor for use with decode()
  virtual AssignAction *clone(const ParamListStandard *newResource) const { return new ConvertToPointer(newResource); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Consume multiple registers to pass a data-type
///
/// Available registers are consumed until the data-type is covered, and an appropriate
/// \e join space address is assigned.  Registers can be consumed from a specific resource list.
/// Consumption can spill over onto the stack if desired.
class MultiSlotAssign : public AssignAction {
  type_class resourceType;		///< Resource list from which to consume
  bool consumeFromStack;		///< True if resources should be consumed from the stack
  bool consumeMostSig;			///< True if resources are consumed starting with most significant bytes
  bool enforceAlignment;		///< True if register resources are discarded to match alignment
  bool justifyRight;			///< True if initial bytes are padding for odd data-type sizes
  vector<const ParamEntry *> tiles;	///< List of registers that can be joined
  const ParamEntry *stackEntry;		///< The stack resource
  void initializeEntries(void);		///< Cache specific ParamEntry needed by the action
public:
  MultiSlotAssign(const ParamListStandard *res);	///< Constructor for use with decode
  MultiSlotAssign(type_class store,bool stack,bool mostSig,bool align,bool justRight,const ParamListStandard *res);	///< Constructor
  virtual AssignAction *clone(const ParamListStandard *newResource) const {
    return new MultiSlotAssign(resourceType,consumeFromStack,consumeMostSig,enforceAlignment,justifyRight,newResource); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual bool fillinOutputMap(ParamActive *active) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Consume a register per primitive member of an aggregate data-type
///
/// The data-type is split up into its underlying primitive elements, and each one
/// is assigned a register from the specific resource list.  There must be no padding between
/// elements.  No packing of elements into a single register occurs.
class MultiMemberAssign : public AssignAction {
  type_class resourceType;		///< Resource list from which to consume
  bool consumeFromStack;		///< True if resources should be consumed from the stack
  bool consumeMostSig;			///< True if resources are consumed starting with most significant bytes
public:
  MultiMemberAssign(type_class store,bool stack,bool mostSig,const ParamListStandard *res);	///< Constructor
  virtual AssignAction *clone(const ParamListStandard *newResource) const {
    return new MultiMemberAssign(resourceType,consumeFromStack,consumeMostSig,newResource); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual bool fillinOutputMap(ParamActive *active) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Consume multiple registers from different storage classes to pass a data-type
///
/// This action is for calling conventions that can use both floating-point and general purpose registers
/// when assigning storage for a single composite data-type, such as the X86-64 System V ABI
class MultiSlotDualAssign : public AssignAction {
  type_class baseType;			///< Resource list from which to consume general tiles
  type_class altType;			///< Resource list from which to consume alternate tiles
  bool consumeMostSig;			///< True if resources are consumed starting with most significant bytes
  bool justifyRight;			///< True if initial bytes are padding for odd data-type sizes
  int4 tileSize;			///< Number of bytes in a tile
  vector<const ParamEntry *> baseTiles;	///< General registers to be joined
  vector<const ParamEntry *> altTiles;	///< Alternate registers to be joined
  void initializeEntries(void);		///< Cache specific ParamEntry needed by the action
  int4 getFirstUnused(int4 iter,const vector<const ParamEntry *> &tiles,vector<int4> &status) const;
  int4 getTileClass(const PrimitiveExtractor &primitives,int4 off,int4 &index) const;
public:
  MultiSlotDualAssign(const ParamListStandard *res);		///< Constructor for use with decode
  MultiSlotDualAssign(type_class baseStore,type_class altStore,bool mostSig,bool justRight,
		      const ParamListStandard *res);	///< Constructor
  virtual AssignAction *clone(const ParamListStandard *newResource) const {
    return new MultiSlotDualAssign(baseType,altType,consumeMostSig,justifyRight,newResource); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual bool fillinOutputMap(ParamActive *active) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Consume a parameter from a specific resource list
///
/// Normally the resource list is determined by the parameter data-type, but this
/// action specifies an overriding resource list.  Assignment will \e not fall through to the stack.
class ConsumeAs : public AssignAction {
  type_class resourceType;		///< The resource list the parameter is consumed from
public:
  ConsumeAs(type_class store,const ParamListStandard *res);	///< Constructor
  virtual AssignAction *clone(const ParamListStandard *newResource) const {
    return new ConsumeAs(resourceType,newResource); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual bool fillinOutputMap(ParamActive *active) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Allocate the return value as an input parameter
///
/// A pointer to where the return value is to be stored is passed in as an input parameter.
/// This action signals this by returning one of
///   - \b hiddenret_ptrparam         - indicating the pointer is allocated as a normal input parameter
///   - \b hiddenret_specialreg       - indicating the pointer is passed in a dedicated register
///   - \b hiddenret_specialreg_void
///
/// Usually, if a hidden return input is present, the normal register used for return
/// will also hold the pointer at the point(s) where the function returns.  A signal of
/// \b hiddenret_specialreg_void indicates the normal return register is not used to pass back
/// the pointer.
class HiddenReturnAssign : public AssignAction {
  uint4 retCode;		///< The specific signal to pass back
public:
  HiddenReturnAssign(const ParamListStandard *res,uint4 code);	///< Constructor
  virtual AssignAction *clone(const ParamListStandard *newResource) const {
    return new HiddenReturnAssign(newResource, retCode); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Consume additional registers from an alternate resource list
///
/// This action is a side-effect and doesn't assign an address for the current parameter.
/// The resource list, \b resourceType, is specified. If the side-effect is triggered,
/// register resources from this list are consumed.  If \b matchSize is true (the default),
/// registers are consumed, until the number of bytes in the data-type is reached.  Otherwise,
/// only a single register is consumed. If all registers are already consumed, no action is taken.
class ConsumeExtra : public AssignAction {
  type_class resourceType;		///< The other resource list to consume from
  bool matchSize;			///< \b false, if side-effect only consumes a single register
  vector<const ParamEntry *> tiles;	///< List of registers that can be consumed
  void initializeEntries(void);		///< Cache specific ParamEntry needed by the action
public:
  ConsumeExtra(const ParamListStandard *res);	///< Constructor for use with decode
  ConsumeExtra(type_class store,bool match,const ParamListStandard *res);	///< Constructor
  virtual AssignAction *clone(const ParamListStandard *newResource) const {
    return new ConsumeExtra(resourceType,matchSize,newResource); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual void decode(Decoder &decoder);
};

/// \brief Consume stack resources as a side-effect
///
/// This action is a side-effect and doesn't assign an address for the current parameter.
/// If the current parameter has been assigned a address that is not on the stack, this action consumes
/// stack resources as if the parameter were allocated to the stack.  If the current parameter was
/// already assigned a stack address, no additional action is taken.
class ExtraStack : public AssignAction {
  const ParamEntry *stackEntry;	///< Parameter Entry corresponding to the stack
  void initializeEntry(void);	///< Find stack entry in resource list
public:
  ExtraStack(const ParamListStandard *res,int4 val);	///< Constructor for use with decode
  ExtraStack(const ParamListStandard *res);	///< Constructor
  virtual AssignAction *clone(const ParamListStandard *newResource) const {
    return new ExtraStack(newResource); }
  virtual uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			      vector<int4> &status,ParameterPieces &res) const;
  virtual void decode(Decoder &decoder);
};

/// \brief A rule controlling how parameters are assigned addresses
///
/// Rules are applied to a parameter in the context of a full function prototype.
/// A rule applies only for a specific class of data-type associated with the parameter, as
/// determined by its DatatypeFilter, and may have other criteria limiting when it applies
/// (via QualifierFilter).
class ModelRule {
  DatatypeFilter *filter;		///< Which data-types \b this rule applies to
  QualifierFilter *qualifier;		///< Additional qualifiers for when the rule should apply (if non-null)
  AssignAction *assign;			///< How the Address should be assigned
  vector<AssignAction *> sideeffects;	///< Extra actions that happen on success
public:
  ModelRule(void) {
    filter = (DatatypeFilter *)0; qualifier = (QualifierFilter *)0; assign = (AssignAction *)0; }	///< Constructor for use with decode
  ModelRule(const ModelRule &op2,const ParamListStandard *res);	///< Copy constructor
  ModelRule(const DatatypeFilter &typeFilter,const AssignAction &action,const ParamListStandard *res);	///< Construct from components
  ~ModelRule(void);	///< Destructor
  uint4 assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
		      vector<int4> &status,ParameterPieces &res) const;
  bool fillinOutputMap(ParamActive *active) const;	///< Test and mark the trial(s) that can be valid return value
  bool canAffectFillinOutput(void) const;		///< Return \b true if fillinOutputMap is active for \b this rule
  void decode(Decoder &decoder,const ParamListStandard *res);		///< Decode \b this rule from stream
};

/// If the assign action could produce the trials as return value storage, return \b true
/// \param active is the set of trials
/// \return \b true if the trials form a return value
inline bool ModelRule::fillinOutputMap(ParamActive *active) const

{
  return assign->fillinOutputMap(active);
}

/// \return \b true if the assign action can affect fillinOutputMap()
inline bool ModelRule::canAffectFillinOutput(void) const

{
  return assign->canAffectFillinOutput();
}

} // End namespace ghidra
#endif
