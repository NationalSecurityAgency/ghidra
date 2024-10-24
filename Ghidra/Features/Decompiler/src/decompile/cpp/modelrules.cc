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
#include "modelrules.hh"
#include "funcdata.hh"

namespace ghidra {

ElementId ELEM_DATATYPE = ElementId("datatype",273);
ElementId ELEM_CONSUME = ElementId("consume",274);
ElementId ELEM_CONSUME_EXTRA = ElementId("consume_extra",275);
ElementId ELEM_CONVERT_TO_PTR = ElementId("convert_to_ptr",276);
ElementId ELEM_GOTO_STACK = ElementId("goto_stack",277);
ElementId ELEM_JOIN = ElementId("join",278);
ElementId ELEM_DATATYPE_AT = ElementId("datatype_at",279);
ElementId ELEM_POSITION = ElementId("position",280);
ElementId ELEM_VARARGS = ElementId("varargs",281);
ElementId ELEM_HIDDEN_RETURN = ElementId("hidden_return",282);
ElementId ELEM_JOIN_PER_PRIMITIVE = ElementId("join_per_primitive",283);
ElementId ELEM_JOIN_DUAL_CLASS = ElementId("join_dual_class",285);

/// \brief Check that a big Primitive properly overlaps smaller Primitives
///
/// If the big Primitive does not properly overlap the smaller Primitives starting at the given \b point,
/// return -1.  Otherwise, if the big Primitive is floating-point, add the overlapped primitives to the
/// common refinement list, or if not a floating-point, add the big Primitive to the list.
/// (Integer primitives are \e preferred over floating-point primitives in this way) Return the index of
/// the next primitive after the overlap.
/// \param res holds the common refinement list
/// \param small is the list of Primitives that are overlapped
/// \param point is the index of the first overlap
/// \param big is the big overlapping Primitive
/// \return the index of the next Primitive after the overlap or -1 if the overlap is invalid
int4 PrimitiveExtractor::checkOverlap(vector<Primitive> &res,vector<Primitive> &small,int4 point,Primitive &big)

{
  int4 endOff = big.offset + big.dt->getAlignSize();
  // If big data-type is a float, let smaller primitives override it, otherwise we keep the big primitive
  bool useSmall = big.dt->getMetatype() == TYPE_FLOAT;
  while(point < small.size()) {
    int4 curOff = small[point].offset;
    if (curOff >= endOff) break;
    curOff += small[point].dt->getAlignSize();
    if (curOff > endOff)
      return -1;			// Improper overlap of the end of big
    if (useSmall)
      res.push_back(small[point]);
    point += 1;
  }
  if (!useSmall)		// If big data-type was preferred
    res.push_back(big);		// use big Primitive in the refinement
  return point;
}

/// \brief Overwrite \b first list with common refinement of \b first and \b second
///
/// Given two sets of overlapping Primitives, find a \e common \e refinement of the lists.
/// If there is any partial overlap of two Primitives, \b false is returned.
/// If the same primitive data-type occurs at the same offset, it is included in the refinement.
/// Otherwise an integer data-type is preferred over a floating-point data-type, or a bigger
/// primitive is preferred over smaller overlapping primitives.
/// The final refinement replaces the \b first list.
/// \param first is the first list of Primitives
/// \param second is the second list
/// \return \b true if a refinement was successfully constructed
bool PrimitiveExtractor::commonRefinement(vector<Primitive> &first,vector<Primitive> &second)

{
  int4 firstPoint = 0;
  int4 secondPoint = 0;
  vector<Primitive> common;
  while(firstPoint < first.size() && secondPoint < second.size()) {
    Primitive &firstElement( first[firstPoint] );
    Primitive &secondElement( second[secondPoint] );
    if (firstElement.offset < secondElement.offset &&
	firstElement.offset + firstElement.dt->getAlignSize() <= secondElement.offset) {
      common.push_back(firstElement);
      firstPoint += 1;
      continue;
    }
    if (secondElement.offset < firstElement.offset &&
	secondElement.offset + secondElement.dt->getAlignSize() <= firstElement.offset) {
      common.push_back(secondElement);
      secondPoint += 1;
      continue;
    }
    if (firstElement.dt->getAlignSize() >= secondElement.dt->getAlignSize()) {
      secondPoint = checkOverlap(common,second,secondPoint,firstElement);
      if (secondPoint < 0) return false;
      firstPoint += 1;
    }
    else {
      firstPoint = checkOverlap(common,first,firstPoint,secondElement);
      if (firstPoint < 0) return false;
      secondPoint += 1;
    }
  }
  // Add any tail primitives from either list
  while(firstPoint < first.size()) {
    common.push_back(first[firstPoint]);
    firstPoint += 1;
  }
  while(secondPoint < second.size()) {
    common.push_back(second[secondPoint]);
    secondPoint += 1;
  }
  first.swap(common);	// Replace first with the refinement
  return true;
}

/// Form a primitive list for each field of the union.  Then, if possible, form a common refinement
/// of all the primitive lists and add to the end of \b this extractor's list.
/// \param dt is the union data-type
/// \param max is the maximum number primitives allowed for \b this extraction
/// \param offset is the starting offset of the union within the parent
/// \return \b true if a common refinement was found and appended
bool PrimitiveExtractor::handleUnion(TypeUnion *dt,int4 max,int4 offset)

{
  if ((flags & union_invalid) != 0)
    return false;
  int4 num = dt->numDepend();
  if (num == 0)
    return false;
  const TypeField *curField = dt->getField(0);
  PrimitiveExtractor common(curField->type,false,offset + curField->offset,max);
  if (!common.isValid())
    return false;
  for(int4 i=1;i<num;++i) {
    curField = dt->getField(i);
    PrimitiveExtractor next(curField->type,false,offset + curField->offset,max);
    if (!next.isValid())
      return false;
    if (!commonRefinement(common.primitives,next.primitives))
      return false;
  }
  if (primitives.size() + common.primitives.size() > max)
    return false;
  for(int4 i=0;i<common.primitives.size();++i)
    primitives.push_back(common.primitives[i]);
  return true;
}

/// An array of the primitive data-types, with their associated offsets, is constructed.
/// If the given data-type is already primitive it is put in the array by itself. Otherwise
/// if it is composite, its components are recursively added to the array.
/// Boolean properties about the primitives encountered are recorded:
///   - Are any of the primitives \b undefined
///   - Are all the primitives properly aligned.
///
/// If a maximum number of extracted primitives is exceeded, or if an illegal
/// data-type is encountered (\b void or other internal data-type) false is returned.
/// \param dt is the given data-type to extract primitives from
/// \param max is the maximum number of primitives to extract before giving up
/// \param offset is the starting offset to associate with the first primitive
/// \return \b true if all primitives were extracted
bool PrimitiveExtractor::extract(Datatype *dt,int4 max,int4 offset)

{
  switch(dt->getMetatype()) {
    case TYPE_UNKNOWN:
      flags |= unknown_element;		///< Mark that the data-type contains an unknown primitive
      // fallthru
    case TYPE_INT:
    case TYPE_UINT:
    case TYPE_BOOL:
    case TYPE_CODE:
    case TYPE_FLOAT:
    case TYPE_PTR:
    case TYPE_PTRREL:
      if (primitives.size() >= max)
	return false;
      primitives.emplace_back(dt,offset);
      return true;
    case TYPE_ARRAY:
    {
      int4 numEls = ((TypeArray *)dt)->numElements();
      Datatype *base = ((TypeArray *)dt)->getBase();
      for(int4 i=0;i<numEls;++i) {
	if (!extract(base,max,offset))
	  return false;
	offset += base->getAlignSize();
      }
      return true;
    }
    case TYPE_UNION:
      return handleUnion((TypeUnion *)dt,max,offset);
    case TYPE_STRUCT:
      break;
    default:
      return false;
  }
  TypeStruct *structPtr = (TypeStruct *)dt;
  vector<TypeField>::const_iterator enditer = structPtr->endField();
  int4 expectedOff = offset;
  for(vector<TypeField>::const_iterator iter=structPtr->beginField();iter!=enditer;++iter) {
    Datatype *compDt = (*iter).type;
    int4 curOff = (*iter).offset + offset;
    int4 align = compDt->getAlignment();
    if (curOff % align != 0)
      flags |= unaligned;
    int4 rem = expectedOff % align;
    if (rem != 0) {
      expectedOff += (align - rem);
    }
    if (expectedOff != curOff) {
      flags |= extra_space;
    }
    if (!extract(compDt,max,curOff))
      return false;
    expectedOff = curOff + compDt->getAlignSize();
 }
  return true;
}

/// \param dt is data-type extract from
/// \param unionIllegal is \b true if unions encountered during extraction are considered illegal
/// \param offset is the starting offset to associate with the data-type
/// \param max is the maximum number of primitives to extract before giving up
PrimitiveExtractor::PrimitiveExtractor(Datatype *dt,bool unionIllegal,int offset,int4 max)

{
  flags = unionIllegal ? union_invalid : 0;
  if (!extract(dt,max,offset))
    flags |= invalid;
}

/// \param decoder is the given stream decoder
/// \return the new data-type filter instance
DatatypeFilter *DatatypeFilter::decodeFilter(Decoder &decoder)

{
  DatatypeFilter *filter;
  uint4 elemId = decoder.openElement(ELEM_DATATYPE);
  string nm = decoder.readString(ATTRIB_NAME);
  if (nm == "any") {
    filter = new SizeRestrictedFilter();
  }
  else if (nm == "homogeneous-float-aggregate") {
    filter = new HomogeneousAggregate(TYPE_FLOAT,4,0,0);
  }
  else {
    // If no other name matches, assume this is a metatype
    type_metatype meta = string2metatype(nm);
    filter = new MetaTypeFilter(meta);
  }
  filter->decode(decoder);
  decoder.closeElement(elemId);
  return filter;
}

SizeRestrictedFilter::SizeRestrictedFilter(int4 min,int4 max)

{
  minSize = min;
  maxSize = max;
  if (maxSize == 0 && minSize >= 0) {
    // If no ATTRIB_MAXSIZE is given, assume there is no upper bound on size
    maxSize = 0x7fffffff;
  }
}

/// If \b maxSize is not zero, the data-type is checked to see if its size in bytes
/// falls between \b minSize and \b maxSize inclusive.
/// \param dt is the data-type to test
/// \return \b true if the data-type meets the size restrictions
bool SizeRestrictedFilter::filterOnSize(Datatype *dt) const

{
  if (maxSize == 0) return true;	// maxSize of 0 means no size filtering is performed
  return (dt->getSize() >= minSize && dt->getSize() <= maxSize);
}

void SizeRestrictedFilter::decode(Decoder &decoder)

{
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_MINSIZE)
      minSize = decoder.readUnsignedInteger();
    else if (attribId == ATTRIB_MAXSIZE)
      maxSize = decoder.readUnsignedInteger();
  }
  if (maxSize == 0 && minSize >= 0) {
    // If no ATTRIB_MAXSIZE is given, assume there is no upper bound on size
    maxSize = 0x7fffffff;
  }
}

MetaTypeFilter::MetaTypeFilter(type_metatype meta)

{
  metaType = meta;
}

MetaTypeFilter::MetaTypeFilter(type_metatype meta,int4 min,int4 max)
  : SizeRestrictedFilter(min,max)
{
  metaType = meta;
}

bool MetaTypeFilter::filter(Datatype *dt) const

{
  if (dt->getMetatype() != metaType) return false;
  return filterOnSize(dt);
}

HomogeneousAggregate::HomogeneousAggregate(type_metatype meta)

{
  metaType = meta;
  maxPrimitives = 2;
}

HomogeneousAggregate::HomogeneousAggregate(type_metatype meta,int4 maxPrim,int4 min,int4 max)
  : SizeRestrictedFilter(min,max)
{
  metaType = meta;
  maxPrimitives = maxPrim;
}

bool HomogeneousAggregate::filter(Datatype *dt) const

{
  type_metatype meta = dt->getMetatype();
  if (meta != TYPE_ARRAY && meta != TYPE_STRUCT)
    return false;
  PrimitiveExtractor primitives(dt,true,0,4);
  if (!primitives.isValid() || primitives.size() == 0 || primitives.containsUnknown()
      || !primitives.isAligned() || primitives.containsHoles())
    return false;
  Datatype *base = primitives.get(0).dt;
  if (base->getMetatype() != metaType)
    return false;
  for(int4 i=1;i<primitives.size();++i) {
    if (primitives.get(i).dt != base)
      return false;
  }
  return true;
}

/// If the next element is a qualifier filter, decode it from the stream and return it.
/// Otherwise return null
/// \param decoder is the given stream decoder
/// \return the new qualifier instance or null
QualifierFilter *QualifierFilter::decodeFilter(Decoder &decoder)

{
  QualifierFilter *filter;
  uint4 elemId = decoder.peekElement();
  if (elemId == ELEM_VARARGS)
    filter = new VarargsFilter();
  else if (elemId == ELEM_POSITION)
    filter = new PositionMatchFilter(-1);
  else if (elemId == ELEM_DATATYPE_AT)
    filter = new DatatypeMatchFilter();
  else
    return (QualifierFilter *)0;
  filter->decode(decoder);
  return filter;
}

/// The AndFilter assumes ownership of all the filters in the array and the original vector is cleared
/// \param filters is the list of filters pulled into \b this filter
AndFilter::AndFilter(vector<QualifierFilter *> filters)

{
  subQualifiers.swap(filters);
}

AndFilter::~AndFilter(void)

{
  for(int4 i=0;i<subQualifiers.size();++i)
    delete subQualifiers[i];
}

QualifierFilter *AndFilter::clone(void) const

{
  vector<QualifierFilter *> newFilters;
  for(int4 i=0;i<subQualifiers.size();++i)
    newFilters.push_back(subQualifiers[i]->clone());
  return new AndFilter(newFilters);
}

bool AndFilter::filter(const PrototypePieces &proto,int4 pos) const

{
  for(int4 i=0;i<subQualifiers.size();++i) {
    if (!subQualifiers[i]->filter(proto,pos))
      return false;
  }
  return true;
}

bool VarargsFilter::filter(const PrototypePieces &proto,int4 pos) const

{
  if (proto.firstVarArgSlot < 0) return false;
  return (pos >= proto.firstVarArgSlot);
}

void VarargsFilter::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_VARARGS);
  decoder.closeElement(elemId);
}

bool PositionMatchFilter::filter(const PrototypePieces &proto,int4 pos) const

{
  return (pos == position);
}

void PositionMatchFilter::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_POSITION);
  position = decoder.readSignedInteger(ATTRIB_INDEX);
  decoder.closeElement(elemId);
}

DatatypeMatchFilter::~DatatypeMatchFilter(void)

{
  if (typeFilter != (DatatypeFilter *)0)
    delete typeFilter;
}

QualifierFilter *DatatypeMatchFilter::clone(void) const

{
  DatatypeMatchFilter *res = new DatatypeMatchFilter();
  res->position = position;
  res->typeFilter = typeFilter->clone();
  return res;
}

bool DatatypeMatchFilter::filter(const PrototypePieces &proto,int4 pos) const

{
  // The position of the current parameter being assigned, pos, is NOT used
  Datatype *dt;
  if (position < 0)
    dt = proto.outtype;
  else {
    if (position >= proto.intypes.size())
      return false;
    dt = proto.intypes[position];
  }
  return typeFilter->filter(dt);
}

void DatatypeMatchFilter::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_DATATYPE_AT);
  position = decoder.readSignedInteger(ATTRIB_INDEX);
  typeFilter = DatatypeFilter::decodeFilter(decoder);
  decoder.closeElement(elemId);
}

bool AssignAction::fillinOutputMap(ParamActive *active) const

{
  return false;		// Default implementation for an inactive action
}

/// \brief Read the next model rule action element from the stream
///
/// Allocate the action object corresponding to the element and configure it.
/// If the next element is not an action, throw an exception.
/// \param decoder is the stream decoder
/// \param res is the resource set for the new action
/// \return the new action
AssignAction *AssignAction::decodeAction(Decoder &decoder,const ParamListStandard *res)

{
  AssignAction *action;
  uint4 elemId = decoder.peekElement();
  if (elemId == ELEM_GOTO_STACK)
    action = new GotoStack(res,0);
  else if (elemId == ELEM_JOIN) {
    action = new MultiSlotAssign(res);
  }
  else if (elemId == ELEM_CONSUME) {
    action = new ConsumeAs(TYPECLASS_GENERAL,res);
  }
  else if (elemId == ELEM_CONVERT_TO_PTR) {
    action = new ConvertToPointer(res);
  }
  else if (elemId == ELEM_HIDDEN_RETURN) {
    action = new HiddenReturnAssign(res,hiddenret_specialreg);
  }
  else if (elemId == ELEM_JOIN_PER_PRIMITIVE) {
    bool consumeMostSig = false;
    AddrSpace *spc = res->getSpacebase();
    if (spc != (AddrSpace *)0 && spc->isBigEndian()) {
      consumeMostSig = true;
     }
    action = new MultiMemberAssign(TYPECLASS_GENERAL,false,consumeMostSig,res);
  }
  else if (elemId == ELEM_JOIN_DUAL_CLASS) {
    action = new MultiSlotDualAssign(res);
  }
  else
    throw DecoderError("Expecting model rule action");
  action->decode(decoder);
  return action;
}

/// \brief Read the next model rule sideeffect element from the stream
///
/// Allocate the sideeffect object corresponding to the element and configure it.
/// If the next element is not a sideeffect, throw an exception.
/// \param decoder is the stream decoder
/// \param res is the resource set for the new sideeffect
/// \return the new sideeffect
AssignAction *AssignAction::decodeSideeffect(Decoder &decoder,const ParamListStandard *res)

{
  AssignAction *action;
  uint4 elemId = decoder.peekElement();

  if (elemId == ELEM_CONSUME_EXTRA) {
    action = new ConsumeExtra(res);
  }
  else
    throw DecoderError("Expecting model rule sideeffect");
  action->decode(decoder);
  return action;
}

void GotoStack::initializeEntry(void)

{
  stackEntry = resource->getStackEntry();
  if (stackEntry == (const ParamEntry *)0)
    throw LowlevelError("Cannot find matching <pentry> for action: gotostack");
}

/// \param res is the new resource set to associate with \b this action
/// \param val is a dummy value
GotoStack::GotoStack(const ParamListStandard *res,int4 val)
  : AssignAction(res)
{
  stackEntry = (const ParamEntry *)0;
  fillinOutputActive = true;
}

GotoStack::GotoStack(const ParamListStandard *res)
  : AssignAction(res)
{
  stackEntry = (const ParamEntry *)0;
  fillinOutputActive = true;
  initializeEntry();
}

uint4 GotoStack::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlst,
			       vector<int4> &status,ParameterPieces &res) const
{
  int4 grp = stackEntry->getGroup();
  res.type = dt;
  res.addr = stackEntry->getAddrBySlot(status[grp],dt->getSize(),dt->getAlignment());
  res.flags = 0;
  return success;
}

bool GotoStack::fillinOutputMap(ParamActive *active) const

{
  int4 count = 0;
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &trial(active->getTrial(i));
    const ParamEntry *entry = trial.getEntry();
    if (entry == (const ParamEntry *)0) break;
    if (entry != stackEntry)
      return false;
    count += 1;
    if (count > 1)
      return false;
  }
  return (count == 1);
}

void GotoStack::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_GOTO_STACK);
  decoder.closeElement(elemId);
  initializeEntry();
}

ConvertToPointer::ConvertToPointer(const ParamListStandard *res)
  : AssignAction(res)
{
  space = res->getSpacebase();
}

uint4 ConvertToPointer::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
				      vector<int4> &status,ParameterPieces &res) const
{
  AddrSpace *spc = space;
  if (spc == (AddrSpace*)0)
    spc = tlist.getArch()->getDefaultDataSpace();
  int4 pointersize = proto.model->getPointerSize(spc);
  int4 wordsize = spc->getWordSize();
  // Convert the data-type to a pointer
  Datatype *pointertp = tlist.getTypePointer(pointersize,dt,wordsize);
  // (Recursively) assign storage
  uint4 responseCode = resource->assignAddress(pointertp, proto, pos, tlist, status, res);
  res.flags = ParameterPieces::indirectstorage;
  return responseCode;
}

void ConvertToPointer::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_CONVERT_TO_PTR);
  decoder.closeElement(elemId);
}

/// Find the first ParamEntry matching the \b resourceType, and the ParamEntry
/// corresponding to the \e stack if \b consumeFromStack is set.
void MultiSlotAssign::initializeEntries(void)

{
  firstIter = resource->getFirstIter(resourceType);
  stackEntry = resource->getStackEntry();
  if (firstIter == resource->getEntry().end())
    throw LowlevelError("Could not find matching resources for action: join");
  if (consumeFromStack && stackEntry == (const ParamEntry *)0)
    throw LowlevelError("Cannot find matching <pentry> for action: join");
}

/// Set default configuration
/// \param res is the new resource set to associate with \b this action
MultiSlotAssign::MultiSlotAssign(const ParamListStandard *res)
  : AssignAction(res)
{
  resourceType = TYPECLASS_GENERAL;	// Join general purpose registers
  fillinOutputActive = true;
  uint4 listType = res->getType();
  // Consume from stack on input parameters by default
  consumeFromStack = (listType != ParamList::p_register_out && listType != ParamList::p_standard_out);
  consumeMostSig = false;
  enforceAlignment = false;
  justifyRight = false;
  AddrSpace *spc = res->getSpacebase();
  if (spc != (AddrSpace *)0 && spc->isBigEndian()) {
    consumeMostSig = true;
    justifyRight = true;
  }
  stackEntry = (const ParamEntry *)0;
}

MultiSlotAssign::MultiSlotAssign(type_class store,bool stack,bool mostSig,bool align,bool justRight,const ParamListStandard *res)
  : AssignAction(res)
{
  resourceType = store;
  fillinOutputActive = true;
  consumeFromStack = stack;
  consumeMostSig = mostSig;
  enforceAlignment = align;
  justifyRight = justRight;
  stackEntry = (const ParamEntry *)0;
  initializeEntries();
}

uint4 MultiSlotAssign::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
				     vector<int4> &status,ParameterPieces &res) const
{
  vector<int4> tmpStatus = status;
  vector<VarnodeData> pieces;
  int4 sizeLeft = dt->getSize();
  list<ParamEntry>::const_iterator iter = firstIter;
  list<ParamEntry>::const_iterator endIter = resource->getEntry().end();
  if (enforceAlignment) {
    int4 resourcesConsumed = 0;
    while(iter != endIter) {
      const ParamEntry &entry( *iter );
      if (!entry.isExclusion())
        break;		// Reached end of resource list
      if (entry.getType() == resourceType && entry.getAllGroups().size() == 1) {	// Single register
	if (tmpStatus[entry.getGroup()] == 0) {		// Not consumed
	  int4 align = dt->getAlignment();
	  int4 regSize = entry.getSize();
	  if (align <= regSize || (resourcesConsumed % align) == 0)
	    break;
	  tmpStatus[entry.getGroup()] = -1;	// Consume unaligned register
	}
	resourcesConsumed += entry.getSize();
      }
      ++iter;
    }
  }
  while(sizeLeft > 0 && iter != endIter) {
    const ParamEntry &entry( *iter );
    ++iter;
    if (!entry.isExclusion())
      break;		// Reached end of resource list
    if (entry.getType() != resourceType || entry.getAllGroups().size() != 1)
      continue;		// Not a single register from desired resource list
    if (tmpStatus[entry.getGroup()] != 0)
      continue;		// Already consumed
    int4 trialSize = entry.getSize();
    Address addr = entry.getAddrBySlot(tmpStatus[entry.getGroup()], trialSize,1);
    tmpStatus[entry.getGroup()] = -1;	// Consume the register
    pieces.push_back(VarnodeData());
    pieces.back().space = addr.getSpace();
    pieces.back().offset = addr.getOffset();
    pieces.back().size = trialSize;
    sizeLeft -= trialSize;
  }
  if (sizeLeft > 0) {				// Have to use stack to get enough bytes
    if (!consumeFromStack)
      return fail;
    int4 grp = stackEntry->getGroup();
    Address addr = stackEntry->getAddrBySlot(tmpStatus[grp],sizeLeft,1);	// Consume all the space we need
    if (addr.isInvalid())
      return fail;
    pieces.push_back(VarnodeData());
    pieces.back().space = addr.getSpace();
    pieces.back().offset = addr.getOffset();
    pieces.back().size = sizeLeft;
  }
  else if (sizeLeft < 0) {			// Have odd data-type size
    if (resourceType == TYPECLASS_FLOAT && pieces.size() == 1) {
      AddrSpaceManager *manager = tlist.getArch();
      VarnodeData &tmp( pieces.front() );
      Address addr = manager->constructFloatExtensionAddress(tmp.getAddr(),tmp.size,dt->getSize());
      tmp.space = addr.getSpace();
      tmp.offset = addr.getOffset();
      tmp.size = dt->getSize();
    }
    else if (justifyRight) {
      pieces.front().offset += -sizeLeft;	// Initial bytes of first entry are padding
      pieces.front().size += sizeLeft;
    }
    else {
      pieces.back().size += sizeLeft;
    }
  }
  status = tmpStatus;				// Commit resource usage for all the pieces
  res.flags = 0;
  res.type = dt;
  if (pieces.size() == 1) {
    res.addr = pieces[0].getAddr();
    return success;
  }
  if (!consumeMostSig) {
    vector<VarnodeData> reverse;
    for(int4 i=pieces.size()-1;i>=0;--i)
      reverse.push_back(pieces[i]);
    pieces.swap(reverse);
  }
  JoinRecord *joinRecord = tlist.getArch()->findAddJoin(pieces, 0);
  res.addr = joinRecord->getUnified().getAddr();
  return success;
}

bool MultiSlotAssign::fillinOutputMap(ParamActive *active) const

{
  int4 count = 0;
  int4 curGroup = -1;
  int4 partial = -1;
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &trial(active->getTrial(i));
    const ParamEntry *entry = trial.getEntry();
    if (entry == (const ParamEntry *)0) break;
    if (entry->getType() != resourceType)	// Trials must come from action's type_class
      return false;
    if (count == 0) {
      if (!entry->isFirstInClass())
	return false;				// Trials must start on first entry of the type_class
    }
    else {
      if (entry->getGroup() != curGroup + 1)			// Trials must be consecutive
	return false;
    }
    curGroup = entry->getGroup();
    if (trial.getSize() != entry->getSize()) {
      if (partial != -1)
	return false;				// At most, one trial can be partial size
      partial = i;
    }
    count += 1;
  }
  if (partial != -1) {
    if (justifyRight) {
      if (partial != 0) return false;
    }
    else {
      if (partial != count - 1) return false;
    }
    ParamTrial &trial(active->getTrial(partial));
    if (justifyRight == consumeMostSig) {
      if (trial.getOffset() != 0)
	return false;			// Partial entry must be least sig bytes
    }
    else {
      if (trial.getOffset() + trial.getSize() != trial.getEntry()->getSize()) {
	return false;			// Partial entry must be most sig bytes
      }
    }
  }
  return (count > 0);
}

void MultiSlotAssign::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_JOIN);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_REVERSEJUSTIFY) {
      if (decoder.readBool())
	justifyRight = !justifyRight;
    }
    else if (attribId == ATTRIB_STORAGE) {
      resourceType = string2typeclass(decoder.readString());
    }
    else if (attribId == ATTRIB_ALIGN) {
      enforceAlignment = decoder.readBool();
    }
  }
  decoder.closeElement(elemId);
  initializeEntries();			// Need new firstIter
}

MultiMemberAssign::MultiMemberAssign(type_class store,bool stack,bool mostSig,const ParamListStandard *res)
  : AssignAction(res)
{
  resourceType = store;
  consumeFromStack = stack;
  consumeMostSig = mostSig;
  fillinOutputActive = true;
}

uint4 MultiMemberAssign::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
				       vector<int4> &status,ParameterPieces &res) const
{
  vector<int4> tmpStatus = status;
  vector<VarnodeData> pieces;
  PrimitiveExtractor primitives(dt,false,0,16);
  if (!primitives.isValid() || primitives.size() == 0 || primitives.containsUnknown()
      || !primitives.isAligned() || primitives.containsHoles())
    return fail;
  ParameterPieces param;
  for(int4 i=0;i<primitives.size();++i) {
    Datatype *curType = primitives.get(i).dt;
    if (resource->assignAddressFallback(resourceType, curType, !consumeFromStack, tmpStatus,param) == fail)
      return fail;
    pieces.push_back(VarnodeData());
    pieces.back().space = param.addr.getSpace();
    pieces.back().offset = param.addr.getOffset();
    pieces.back().size = curType->getSize();
  }

  status = tmpStatus;				// Commit resource usage for all the pieces
  res.flags = 0;
  res.type = dt;
  if (pieces.size() == 1) {
    res.addr = pieces[0].getAddr();
    return success;
  }
  if (!consumeMostSig) {
    vector<VarnodeData> reverse;
    for(int4 i=pieces.size()-1;i>=0;--i)
      reverse.push_back(pieces[i]);
    pieces.swap(reverse);
  }
  JoinRecord *joinRecord = tlist.getArch()->findAddJoin(pieces, 0);
  res.addr = joinRecord->getUnified().getAddr();
  return success;
}

bool MultiMemberAssign::fillinOutputMap(ParamActive *active) const

{
  int4 count = 0;
  int4 curGroup = -1;
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &trial(active->getTrial(i));
    const ParamEntry *entry = trial.getEntry();
    if (entry == (const ParamEntry *)0) break;
    if (entry->getType() != resourceType)	// Trials must come from action's type_class
      return false;
    if (count == 0) {
      if (!entry->isFirstInClass())
	return false;
    }
    else {
      if (entry->getGroup() != curGroup + 1)			// Trials must be consecutive
	return false;
    }
    curGroup = entry->getGroup();
    if (trial.getOffset() != 0)
      return false;			// Entry must be justified
    count += 1;
  }
  return (count > 0);
}

void MultiMemberAssign::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_JOIN_PER_PRIMITIVE);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_STORAGE) {
      resourceType = string2typeclass(decoder.readString());
    }
  }
  decoder.closeElement(elemId);
}

/// Find the first ParamEntry matching the \b baseType, and the first matching \b altType.
void MultiSlotDualAssign::initializeEntries(void)

{
  baseIter = resource->getFirstIter(baseType);
  altIter = resource->getFirstIter(altType);
  list<ParamEntry>::const_iterator enditer = resource->getEntry().end();
  if (baseIter == enditer || altIter == enditer)
    throw LowlevelError("Could not find matching resources for action: join_dual_class");
  tileSize = (*baseIter).getSize();
  if (tileSize != (*altIter).getSize())
    throw LowlevelError("Storage class register sizes do not match for action: join_dual_class");
}

/// \brief Get the first unused ParamEntry that matches the given storage class
///
/// \param iter points to the starting entry to search
/// \param storage is the given storage class to match
/// \param status is the usage information for the entries
/// \return the iterator to the unused ParamEntry
list<ParamEntry>::const_iterator MultiSlotDualAssign::getFirstUnused(list<ParamEntry>::const_iterator iter,
								     type_class storage,vector<int4> &status) const
{
  list<ParamEntry>::const_iterator endIter = resource->getEntry().end();
  for(;iter != endIter; ++iter) {
    const ParamEntry &entry( *iter );
    if (!entry.isExclusion())
      break;		// Reached end of resource list
    if (entry.getType() != storage || entry.getAllGroups().size() != 1)
      continue;		// Not a single register from desired resource
    if (status[entry.getGroup()] != 0)
      continue;		// Already consumed
    return iter;
  }
  return endIter;
}

/// \brief Get the storage class to use for the specific section of the data-type
///
/// For the section starting at \b off extending through \b tileSize bytes, if any primitive overlaps
/// the boundary of the section, return -1. Otherwise, if all the primitive data-types in the section
/// match the alternate storage class, return 1, or if one or more does not match, return 0.
/// The \b index of the first primitive after the start of the section is provided and is then updated
/// to be the first primitive after the end of the section.
/// \param primitives is the list of primitive data-types making up the data-type
/// \param off is the starting offset of the section
/// \param index is the index of the first primitive in the section
/// \return 0 for a base tile, 1 for an alternate tile, -1 for boundary overlaps
int4 MultiSlotDualAssign::getTileClass(const PrimitiveExtractor &primitives,int4 off,int4 &index) const

{
  int4 res = 1;
  int4 count = 0;
  int4 endBoundary = off + tileSize;
  while(index < primitives.size()) {
    const PrimitiveExtractor::Primitive &element( primitives.get(index) );
    if (element.offset < off) return -1;
    if (element.offset >= endBoundary) break;
    if (element.offset + element.dt->getSize() > endBoundary) return -1;
    count += 1;
    index += 1;
    type_class storage = metatype2typeclass(element.dt->getMetatype());
    if (storage != altType)
      res = 0;
  }
  if (count == 0) return -1;	// Must be at least one primitive in section
  return res;
}

/// Set default configuration
/// \param res is the new resource set to associate with \b this action
MultiSlotDualAssign::MultiSlotDualAssign(const ParamListStandard *res)
  : AssignAction(res)
{
  fillinOutputActive = true;
  baseType = TYPECLASS_GENERAL;		// Tile from general purpose registers
  altType = TYPECLASS_FLOAT;		// Use specialized registers for floating-point components
  consumeMostSig = false;
  justifyRight = false;
  AddrSpace *spc = res->getSpacebase();
  if (spc != (AddrSpace *)0 && spc->isBigEndian()) {
    consumeMostSig = true;
    justifyRight = true;
  }
  tileSize = 0;
}

MultiSlotDualAssign::MultiSlotDualAssign(type_class baseStore,type_class altStore,bool mostSig,bool justRight,
					 const ParamListStandard *res)
  : AssignAction(res)
{
  fillinOutputActive = true;
  baseType = baseStore;
  altType = altStore;
  consumeMostSig = mostSig;
  justifyRight = justRight;
  initializeEntries();
}

uint4 MultiSlotDualAssign::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
					 vector<int4> &status,ParameterPieces &res) const
{
  PrimitiveExtractor primitives(dt,false,0,1024);
  if (!primitives.isValid() || primitives.size() == 0 || primitives.containsHoles())
    return fail;
  int4 primitiveIndex = 0;
  vector<int4> tmpStatus = status;
  vector<VarnodeData> pieces;
  int4 typeSize = dt->getSize();
  int4 sizeLeft = typeSize;
  list<ParamEntry>::const_iterator iterBase = baseIter;
  list<ParamEntry>::const_iterator iterAlt = altIter;
  list<ParamEntry>::const_iterator endIter = resource->getEntry().end();
  while(sizeLeft > 0) {
    list<ParamEntry>::const_iterator iter;
    int4 iterType = getTileClass(primitives, typeSize-sizeLeft, primitiveIndex);
    if (iterType < 0)
      return fail;
    if (iterType == 0) {
      iter = iterBase = getFirstUnused(iterBase, baseType, tmpStatus);
    }
    else {
      iter = iterAlt = getFirstUnused(iterAlt, altType, tmpStatus);
    }
    if (iter == endIter)
      return fail;	// Out of the particular resource
    const ParamEntry &entry( *iter );
    int4 trialSize = entry.getSize();
    Address addr = entry.getAddrBySlot(tmpStatus[entry.getGroup()], trialSize,1);
    tmpStatus[entry.getGroup()] = -1;	// Consume the register
    pieces.push_back(VarnodeData());
    pieces.back().space = addr.getSpace();
    pieces.back().offset = addr.getOffset();
    pieces.back().size = trialSize;
    sizeLeft -= trialSize;
  }
  if (sizeLeft < 0) {			// Have odd data-type size
    if (justifyRight) {
      pieces.front().offset += -sizeLeft;	// Initial bytes of first entry are padding
      pieces.front().size += sizeLeft;
    }
    else {
      pieces.back().size += sizeLeft;
    }
  }
  status = tmpStatus;				// Commit resource usage for all the pieces
  res.flags = 0;
  res.type = dt;
  if (pieces.size() == 1) {
    res.addr = pieces[0].getAddr();
    return success;
  }
  if (!consumeMostSig) {
    vector<VarnodeData> reverse;
    for(int4 i=pieces.size()-1;i>=0;--i)
      reverse.push_back(pieces[i]);
    pieces.swap(reverse);
  }
  JoinRecord *joinRecord = tlist.getArch()->findAddJoin(pieces, 0);
  res.addr = joinRecord->getUnified().getAddr();
  return success;
}

bool MultiSlotDualAssign::fillinOutputMap(ParamActive *active) const

{
  int4 count = 0;
  int4 curGroup = -1;
  int4 partial = -1;
  type_class resourceType = TYPECLASS_GENERAL;
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &trial(active->getTrial(i));
    const ParamEntry *entry = trial.getEntry();
    if (entry == (const ParamEntry *)0) break;
    if (count == 0) {
      resourceType = entry->getType();
      if (resourceType != baseType && resourceType != altType)
	return false;
    }
    else if (entry->getType() != resourceType)	// Trials must come from action's type_class
      return false;
    if (count == 0) {
      if (!entry->isFirstInClass())
	return false;				// Trials must start on first entry of the type_class
    }
    else {
      if (entry->getGroup() != curGroup + 1)			// Trials must be consecutive
	return false;
    }
    curGroup = entry->getGroup();
    if (trial.getSize() != entry->getSize()) {
      if (partial != -1)
	return false;				// At most, one trial can be partial size
      partial = i;
    }
    count += 1;
  }
  if (partial != -1) {
    if (justifyRight) {
      if (partial != 0) return false;
    }
    else {
      if (partial != count - 1) return false;
    }
    ParamTrial &trial(active->getTrial(partial));
    if (justifyRight == consumeMostSig) {
      if (trial.getOffset() != 0)
	return false;			// Partial entry must be least sig bytes
    }
    else {
      if (trial.getOffset() + trial.getSize() != trial.getEntry()->getSize()) {
	return false;			// Partial entry must be most sig bytes
      }
    }
  }
  return (count > 0);

}

void MultiSlotDualAssign::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_JOIN_DUAL_CLASS);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_REVERSEJUSTIFY) {
      if (decoder.readBool())
	justifyRight = !justifyRight;
    }
    else if (attribId == ATTRIB_STORAGE || attribId == ATTRIB_A) {
      baseType = string2typeclass(decoder.readString());
    }
    else if (attribId == ATTRIB_B) {
      altType = string2typeclass(decoder.readString());
    }
  }
  decoder.closeElement(elemId);
  initializeEntries();			// Need new firstIter
}

ConsumeAs::ConsumeAs(type_class store,const ParamListStandard *res)
  : AssignAction(res)
{
  resourceType = store;
  fillinOutputActive = true;
}

uint4 ConsumeAs::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			       vector<int4> &status,ParameterPieces &res) const
{
  return resource->assignAddressFallback(resourceType, dt, true, status, res);
}

bool ConsumeAs::fillinOutputMap(ParamActive *active) const

{
  int4 count = 0;
  for(int4 i=0;i<active->getNumTrials();++i) {
    ParamTrial &trial(active->getTrial(i));
    const ParamEntry *entry = trial.getEntry();
    if (entry == (const ParamEntry *)0) break;
    if (entry->getType() != resourceType)	// Trials must come from action's type_class
      return false;
    if (!entry->isFirstInClass())
      return false;
    count += 1;
    if (count > 1)
      return false;
    if (trial.getOffset() != 0)
      return false;			// Entry must be justified
  }
  return (count > 0);
}

void ConsumeAs::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_CONSUME);
  resourceType = string2typeclass(decoder.readString(ATTRIB_STORAGE));
  decoder.closeElement(elemId);
}

HiddenReturnAssign::HiddenReturnAssign(const ParamListStandard *res,uint4 code)
  : AssignAction(res)
{
  retCode = code;
}

uint4 HiddenReturnAssign::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
					vector<int4> &status,ParameterPieces &res) const
{
  return retCode;		// Signal to assignMap to use TYPECLASS_HIDDENRET
}

void HiddenReturnAssign::decode(Decoder &decoder)

{
  retCode = hiddenret_specialreg;
  uint4 elemId = decoder.openElement(ELEM_HIDDEN_RETURN);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == ATTRIB_VOIDLOCK)
      retCode = hiddenret_specialreg_void;
    else if (attribId == ATTRIB_STRATEGY) {
      string strategyString = decoder.readString();
      if (strategyString == "normalparam")
	retCode = hiddenret_ptrparam;
      else if (strategyString == "special")
	retCode = hiddenret_specialreg;
      else
	throw DecoderError("Bad <hidden_return> strategy: " + strategyString);
    }
    else
      break;
  }
  decoder.closeElement(elemId);
}

/// Find the first ParamEntry matching the \b resourceType.
void ConsumeExtra::initializeEntries(void)

{
  firstIter = resource->getFirstIter(resourceType);
  if (firstIter == resource->getEntry().end())
    throw LowlevelError("Could not find matching resources for action: consumeextra");
}

ConsumeExtra::ConsumeExtra(const ParamListStandard *res)
  : AssignAction(res)
{
  resourceType = TYPECLASS_GENERAL;
  matchSize = true;
}

ConsumeExtra::ConsumeExtra(type_class store,bool match,const ParamListStandard *res)
  : AssignAction(res)
{
  resourceType = store;
  matchSize = match;
  initializeEntries();
}

uint4 ConsumeExtra::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
				     vector<int4> &status,ParameterPieces &res) const
{
  list<ParamEntry>::const_iterator iter = firstIter;
  list<ParamEntry>::const_iterator endIter = resource->getEntry().end();
  int4 sizeLeft = dt->getSize();
  while(sizeLeft > 0 && iter != endIter) {
    const ParamEntry &entry(*iter);
    ++iter;
    if (!entry.isExclusion())
      break;		// Reached end of resource list
    if (entry.getType() != resourceType || entry.getAllGroups().size() != 1)
      continue;		// Not a single register in desired list
    if (status[entry.getGroup()] != 0)
      continue;		// Already consumed
    status[entry.getGroup()] = -1;	// Consume the slot/register
    sizeLeft -= entry.getSize();
    if (!matchSize)
      break;		// Only consume a single register
  }
  return success;
}

void ConsumeExtra::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_CONSUME_EXTRA);
  resourceType = string2typeclass(decoder.readString(ATTRIB_STORAGE));
  decoder.closeElement(elemId);
  initializeEntries();
}

ModelRule::ModelRule(const ModelRule &op2,const ParamListStandard *res)

{
  if (op2.filter != (DatatypeFilter *)0)
    filter = op2.filter->clone();
  else
    filter = (DatatypeFilter *)0;
  if (op2.qualifier != (QualifierFilter *)0)
    qualifier = op2.qualifier->clone();
  else
    qualifier = (QualifierFilter *)0;
  if (op2.assign != (AssignAction *)0)
    assign = op2.assign->clone(res);
  else
    assign = (AssignAction *)0;
  for(int4 i=0;i<op2.sideeffects.size();++i)
    sideeffects.push_back(op2.sideeffects[i]->clone(res));
}

/// The provided components are cloned into the new object.
/// \param typeFilter is the data-type filter the rule applies before performing the action
/// \param action is the action that will be applied
/// \param res is the resource list to which \b this rule will be applied
ModelRule::ModelRule(const DatatypeFilter &typeFilter,const AssignAction &action,const ParamListStandard *res)

{
  filter = typeFilter.clone();
  qualifier = (QualifierFilter *)0;
  assign = action.clone(res);
}

ModelRule::~ModelRule(void)

{
  if (filter != (DatatypeFilter *)0)
    delete filter;
  if (qualifier != (QualifierFilter *)0)
    delete qualifier;
  if (assign != (AssignAction *)0)
    delete assign;
  for(int4 i=0;i<sideeffects.size();++i)
    delete sideeffects[i];
}

/// \brief Assign an address and other details for a specific parameter or for return storage in context
///
/// The Address is only assigned if the data-type filter and the optional qualifier filter
/// pass, otherwise a \b fail response is returned.
/// If the filters pass, the Address is assigned based on the AssignAction specific to
/// \b this rule, and the action's response code is returned.
/// \param dt is the data-type of the parameter or return value
/// \param proto is the high-level description of the function prototype
/// \param pos is the position of the parameter (pos>=0) or return storage (pos=-1)
/// \param tlist is a data-type factory for (possibly) transforming the data-type
/// \param status is the resource consumption array
/// \param res will hold the resulting description of the parameter
/// \return the response code
uint4 ModelRule::assignAddress(Datatype *dt,const PrototypePieces &proto,int4 pos,TypeFactory &tlist,
			       vector<int4> &status,ParameterPieces &res) const
{
  if (!filter->filter(dt)) {
    return AssignAction::fail;
  }
  if (qualifier != (QualifierFilter *)0 && !qualifier->filter(proto,pos)) {
    return AssignAction::fail;
  }
  uint4 response = assign->assignAddress(dt,proto,pos,tlist,status,res);
  if (response != AssignAction::fail) {
    for(int4 i=0;i<sideeffects.size();++i) {
      sideeffects[i]->assignAddress(dt,proto,pos,tlist,status,res);
    }
  }
  return response;
}

/// \param decoder is the stream decoder
/// \param res is the parameter resource list owning \b this rule
void ModelRule::decode(Decoder &decoder,const ParamListStandard *res)

{
  vector<QualifierFilter *> qualifiers;
  uint4 elemId = decoder.openElement(ELEM_RULE);
  filter = DatatypeFilter::decodeFilter(decoder);
  for(;;) {
    QualifierFilter *qual = QualifierFilter::decodeFilter(decoder);
    if (qual == (QualifierFilter *)0)
      break;
    qualifiers.push_back(qual);
  }
  if (qualifiers.size() == 0)
    qualifier = (QualifierFilter *)0;
  else if (qualifiers.size() == 1) {
    qualifier = qualifiers[0];
    qualifiers.clear();
  }
  else {
    qualifier = new AndFilter(qualifiers);
  }
  assign = AssignAction::decodeAction(decoder, res);
  while(decoder.peekElement() != 0) {
    sideeffects.push_back(AssignAction::decodeSideeffect(decoder,res));
  }

  decoder.closeElement(elemId);
}

} // End namespace ghidra
