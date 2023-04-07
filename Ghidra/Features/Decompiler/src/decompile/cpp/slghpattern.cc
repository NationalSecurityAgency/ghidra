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
#include "slghpattern.hh"

namespace ghidra {

uintm DisjointPattern::getMask(int4 startbit,int4 size,bool context) const

{
  PatternBlock *block = getBlock(context);
  if (block != (PatternBlock *)0)
    return block->getMask(startbit,size);
  return 0;
}

uintm DisjointPattern::getValue(int4 startbit,int4 size,bool context) const

{
  PatternBlock *block = getBlock(context);
  if (block != (PatternBlock *)0)
    return block->getValue(startbit,size);
  return 0;
}

int4 DisjointPattern::getLength(bool context) const

{
  PatternBlock *block = getBlock(context);
  if (block != (PatternBlock *)0)
    return block->getLength();
  return 0;
}

bool DisjointPattern::specializes(const DisjointPattern *op2) const

{				// Return true, if everywhere this's mask is non-zero
				// op2's mask is non-zero and op2's value match this's
  PatternBlock *a,*b;

  a = getBlock(false);
  b = op2->getBlock(false);
  if ((b != (PatternBlock *)0)&&(!b->alwaysTrue())) {	// a must match existing block
    if (a == (PatternBlock *)0) return false;
    if (!a->specializes(b)) return false;
  }
  a = getBlock(true);
  b = op2->getBlock(true);
  if ((b != (PatternBlock *)0)&&(!b->alwaysTrue())) {	// a must match existing block
    if (a == (PatternBlock *)0) return false;
    if (!a->specializes(b)) return false;
  }
  return true;
}

bool DisjointPattern::identical(const DisjointPattern *op2) const

{				// Return true if patterns match exactly
  PatternBlock *a,*b;
  
  a = getBlock(false);
  b = op2->getBlock(false);
  if (b != (PatternBlock *)0) {	// a must match existing block
    if (a == (PatternBlock *)0) {
      if (!b->alwaysTrue())
	return false;
    }
    else if (!a->identical(b))
      return false;
  }
  else {
    if ((a != (PatternBlock *)0)&&(!a->alwaysTrue()))
      return false;
  }
  a = getBlock(true);
  b = op2->getBlock(true);
  if (b != (PatternBlock *)0) {	// a must match existing block
    if (a == (PatternBlock *)0) {
      if (!b->alwaysTrue())
	return false;
    }
    else if (!a->identical(b))
      return false;
  }
  else {
    if ((a != (PatternBlock *)0)&&(!a->alwaysTrue()))
      return false;
  }
  return true;
}

static bool resolveIntersectBlock(PatternBlock *bl1,PatternBlock *bl2,PatternBlock *thisblock)

{
  PatternBlock *inter;
  bool allocated = false;
  bool res = true;

  if (bl1 == (PatternBlock *)0)
    inter = bl2;
  else if (bl2 == (PatternBlock *)0)
    inter = bl1;
  else {
    allocated = true;
    inter = bl1->intersect(bl2);
  }
  if (inter == (PatternBlock *)0) {
    if (thisblock != (PatternBlock *)0)
      res = false;
  }
  else if (thisblock == (PatternBlock *)0)
    res = false;
  else
    res = thisblock->identical(inter);
  if (allocated)
    delete inter;
  return res;
}

bool DisjointPattern::resolvesIntersect(const DisjointPattern *op1,const DisjointPattern *op2) const

{ // Is this pattern equal to the intersection of -op1- and -op2-
  if (!resolveIntersectBlock(op1->getBlock(false),op2->getBlock(false),getBlock(false)))
    return false;
  return resolveIntersectBlock(op1->getBlock(true),op2->getBlock(true),getBlock(true));
}

DisjointPattern *DisjointPattern::restoreDisjoint(const Element *el)

{				// DisjointPattern factory
  DisjointPattern *res;
  if (el->getName() == "instruct_pat")
    res = new InstructionPattern();
  else if (el->getName() == "context_pat")
    res = new ContextPattern();
  else
    res = new CombinePattern();
  res->restoreXml(el);
  return res;
}

void PatternBlock::normalize(void)

{
  if (nonzerosize<=0) {		// Check if alwaystrue or alwaysfalse
    offset = 0;			// in which case we don't need mask and value
    maskvec.clear();
    valvec.clear();
    return;
  }
  vector<uintm>::iterator iter1,iter2;
  
  iter1 = maskvec.begin();	// Cut zeros from beginning of mask
  iter2 = valvec.begin();
  while((iter1 != maskvec.end())&&((*iter1)==0)) {
    iter1++;
    iter2++;
    offset += sizeof(uintm);
  }
  maskvec.erase(maskvec.begin(),iter1);
  valvec.erase(valvec.begin(),iter2);

  if (!maskvec.empty()) {
    int4 suboff = 0;		// Cut off unaligned zeros from beginning of mask
    uintm tmp = maskvec[0];
    while(tmp != 0) {
      suboff += 1;
      tmp >>= 8;
    }
    suboff = sizeof(uintm)-suboff;
    if (suboff != 0) {
      offset += suboff;		// Slide up maskvec by suboff bytes
      for(int4 i=0;i<maskvec.size()-1;++i) {
	tmp = maskvec[i] << (suboff*8);
	tmp |= (maskvec[i+1] >> ((sizeof(uintm)-suboff)*8));
	maskvec[i] = tmp;
      }
      maskvec.back() <<= suboff*8;
      for(int4 i=0;i<valvec.size()-1;++i) { // Slide up valvec by suboff bytes
	tmp = valvec[i] << (suboff*8);
	tmp |= (valvec[i+1] >> ((sizeof(uintm)-suboff)*8));
	valvec[i] = tmp;
      }
      valvec.back() <<= suboff*8;
    }
    
    iter1 = maskvec.end();	// Cut zeros from end of mask
    iter2 = valvec.end();
    while(iter1 != maskvec.begin()) {
      --iter1;
      --iter2;
      if ((*iter1) != 0) break; // Find last non-zero
    }
    if (iter1 != maskvec.end()) {
      iter1++;			// Find first zero, in last zero chain
      iter2++;
    }
    maskvec.erase(iter1,maskvec.end());
    valvec.erase(iter2,valvec.end());
  }

  if (maskvec.empty()) {
    offset = 0;
    nonzerosize = 0;		// Always true
    return;
  }
  nonzerosize = maskvec.size() * sizeof(uintm);
  uintm tmp = maskvec.back();	// tmp must be nonzero
  while( (tmp&0xff) == 0) {
    nonzerosize -= 1;
    tmp >>= 8;
  }
}

PatternBlock::PatternBlock(int4 off,uintm msk,uintm val)

{				// Define mask and value pattern, confined to one uintm
  offset = off;
  maskvec.push_back(msk);
  valvec.push_back(val);
  nonzerosize = sizeof(uintm);	// Assume all non-zero bytes before normalization
  normalize();
}

PatternBlock::PatternBlock(bool tf)

{
  offset = 0;
  if (tf)
    nonzerosize = 0;
  else
    nonzerosize = -1;
}

PatternBlock::PatternBlock(const PatternBlock *a,const PatternBlock *b)

{				// Construct PatternBlock by ANDing two others together
  PatternBlock *res = a->intersect(b);
  offset = res->offset;
  nonzerosize = res->nonzerosize;
  maskvec = res->maskvec;
  valvec = res->valvec;
  delete res;
}

PatternBlock::PatternBlock(vector<PatternBlock *> &list)

{				// AND several blocks together to construct new block
  PatternBlock *res,*next;

  if (list.empty()) {		// If not ANDing anything
    offset = 0;			// make constructed block always true
    nonzerosize = 0;
    return;
  }
  res = list[0];
  for(int4 i=1;i<list.size();++i) {
    next = res->intersect(list[i]);
    delete res;
    res = next;
  }
  offset = res->offset;
  nonzerosize = res->nonzerosize;
  maskvec = res->maskvec;
  valvec = res->valvec;
  delete res;
}

PatternBlock *PatternBlock::clone(void) const

{
  PatternBlock *res = new PatternBlock(true);

  res->offset = offset;
  res->nonzerosize = nonzerosize;
  res->maskvec = maskvec;
  res->valvec = valvec;
  return res;
}

PatternBlock *PatternBlock::commonSubPattern(const PatternBlock *b) const

{				// The resulting pattern has a 1-bit in the mask
				// only if the two pieces have a 1-bit and the
				// values agree
  PatternBlock *res = new PatternBlock(true);
  int4 maxlength = (getLength() > b->getLength()) ? getLength() : b->getLength();

  res->offset = 0;
  int4 offset = 0;
  uintm mask1,val1,mask2,val2;
  uintm resmask,resval;
  while(offset < maxlength) {
    mask1 = getMask(offset*8,sizeof(uintm)*8);
    val1 = getValue(offset*8,sizeof(uintm)*8);
    mask2 = b->getMask(offset*8,sizeof(uintm)*8);
    val2 = b->getValue(offset*8,sizeof(uintm)*8);
    resmask = mask1 & mask2 & ~(val1^val2);
    resval = val1 & val2 & resmask;
    res->maskvec.push_back(resmask);
    res->valvec.push_back(resval);
    offset += sizeof(uintm);
  }
  res->nonzerosize = maxlength;
  res->normalize();
  return res;
}

PatternBlock *PatternBlock::intersect(const PatternBlock *b) const

{ // Construct the intersecting pattern
  if (alwaysFalse() || b->alwaysFalse())
    return new PatternBlock(false);
  PatternBlock *res = new PatternBlock(true);
  int4 maxlength = (getLength() > b->getLength()) ? getLength() : b->getLength();

  res->offset = 0;
  int4 offset = 0;
  uintm mask1,val1,mask2,val2,commonmask;
  uintm resmask,resval;
  while(offset < maxlength) {
    mask1 = getMask(offset*8,sizeof(uintm)*8);
    val1 = getValue(offset*8,sizeof(uintm)*8);
    mask2 = b->getMask(offset*8,sizeof(uintm)*8);
    val2 = b->getValue(offset*8,sizeof(uintm)*8);
    commonmask = mask1 & mask2;	// Bits in mask shared by both patterns
    if ((commonmask & val1) != (commonmask & val2)) {
      res->nonzerosize = -1;	// Impossible pattern
      res->normalize();
      return res;
    }
    resmask = mask1 | mask2;
    resval = (mask1 & val1) | (mask2 & val2);
    res->maskvec.push_back(resmask);
    res->valvec.push_back(resval);
    offset += sizeof(uintm);
  }
  res->nonzerosize = maxlength;
  res->normalize();
  return res;
}

bool PatternBlock::specializes(const PatternBlock *op2) const

{				// does every masked bit in -this- match the corresponding
				// masked bit in -op2-
  int4 length = 8*op2->getLength();
  int4 tmplength;
  uintm mask1,mask2,value1,value2;
  int4 sbit = 0;
  while(sbit < length) {
    tmplength = length-sbit;
    if (tmplength > 8*sizeof(uintm))
      tmplength = 8*sizeof(uintm);
    mask1 = getMask(sbit,tmplength);
    value1 = getValue(sbit,tmplength);
    mask2 = op2->getMask(sbit,tmplength);
    value2 = op2->getValue(sbit,tmplength);
    if ((mask1 & mask2) != mask2) return false;
    if ((value1 & mask2) != (value2 & mask2)) return false;
    sbit += tmplength;
  }
  return true;
}

bool PatternBlock::identical(const PatternBlock *op2) const

{				// Do the mask and value match exactly
  int4 tmplength;
  int4 length = 8*op2->getLength();
  tmplength = 8*getLength();
  if (tmplength > length)
    length = tmplength;		// Maximum of two lengths
  uintm mask1,mask2,value1,value2;
  int4 sbit = 0;
  while(sbit < length) {
    tmplength = length-sbit;
    if (tmplength > 8*sizeof(uintm))
      tmplength = 8*sizeof(uintm);
    mask1 = getMask(sbit,tmplength);
    value1 = getValue(sbit,tmplength);
    mask2 = op2->getMask(sbit,tmplength);
    value2 = op2->getValue(sbit,tmplength);
    if (mask1 != mask2) return false;
    if ((mask1&value1) != (mask2&value2)) return false;
    sbit += tmplength;
  }
  return true;
}

uintm PatternBlock::getMask(int4 startbit,int4 size) const

{
  startbit -= 8*offset;
  // Note the division and remainder here is unsigned.  Then it is recast to signed. 
  // If startbit is negative, then wordnum1 is either negative or very big,
  // if (unsigned size is same as sizeof int)
  // In either case, shift should come out between 0 and 8*sizeof(uintm)-1
  int4 wordnum1 = startbit/(8*sizeof(uintm));
  int4 shift = startbit % (8*sizeof(uintm));
  int4 wordnum2 = (startbit+size-1)/(8*sizeof(uintm));
  uintm res;

  if ((wordnum1<0)||(wordnum1>=maskvec.size()))
    res = 0;
  else
    res = maskvec[wordnum1];

  res <<= shift;
  if (wordnum1 != wordnum2) {
    uintm tmp;
    if ((wordnum2<0)||(wordnum2>=maskvec.size()))
      tmp = 0;
    else
      tmp = maskvec[wordnum2];
    res |= (tmp>>(8*sizeof(uintm)-shift));
  }
  res >>= (8*sizeof(uintm) - size);
  
  return res;
}

uintm PatternBlock::getValue(int4 startbit,int4 size) const

{
  startbit -= 8*offset;
  int4 wordnum1 = startbit/(8*sizeof(uintm));
  int4 shift = startbit % (8*sizeof(uintm));
  int4 wordnum2 = (startbit+size-1)/(8*sizeof(uintm));
  uintm res;

  if ((wordnum1<0)||(wordnum1>=valvec.size()))
    res = 0;
  else
    res = valvec[wordnum1];
  res <<= shift;
  if (wordnum1 != wordnum2) {
    uintm tmp;
    if ((wordnum2<0)||(wordnum2>=valvec.size()))
      tmp = 0;
    else
      tmp = valvec[wordnum2];
    res |= (tmp>>(8*sizeof(uintm)-shift));
  }
  res >>= (8*sizeof(uintm) - size);
  
  return res;
}

bool PatternBlock::isInstructionMatch(ParserWalker &walker) const

{
  if (nonzerosize<=0) return (nonzerosize==0);
  int4 off = offset;
  for(int4 i=0;i<maskvec.size();++i) {
    uintm data = walker.getInstructionBytes(off,sizeof(uintm));
    if ((maskvec[i] & data)!=valvec[i]) return false;
    off += sizeof(uintm);
  }
  return true;
}

bool PatternBlock::isContextMatch(ParserWalker &walker) const

{
  if (nonzerosize<=0) return (nonzerosize==0);
  int4 off = offset;
  for(int4 i=0;i<maskvec.size();++i) {
    uintm data = walker.getContextBytes(off,sizeof(uintm));
    if ((maskvec[i] & data)!=valvec[i]) return false;
    off += sizeof(uintm);
  }
  return true;
}

void PatternBlock::saveXml(ostream &s) const

{
  s << "<pat_block ";
  s << "offset=\"" << dec << offset << "\" ";
  s << "nonzero=\"" << nonzerosize << "\">\n";
  for(int4 i=0;i<maskvec.size();++i) {
    s << "  <mask_word ";
    s << "mask=\"0x" << hex << maskvec[i] << "\" ";
    s << "val=\"0x" << valvec[i] << "\"/>\n";
  }
  s << "</pat_block>\n";
}

void PatternBlock::restoreXml(const Element *el)

{
  {
    istringstream s(el->getAttributeValue("offset"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> offset;
  }
  {
    istringstream s(el->getAttributeValue("nonzero"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> nonzerosize;
  }
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  uintm mask,val;
  while(iter != list.end()) {
    Element *subel = *iter;
    {
      istringstream s(subel->getAttributeValue("mask"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> mask;
    }
    {
      istringstream s(subel->getAttributeValue("val"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> val;
    }
    maskvec.push_back(mask);
    valvec.push_back(val);
    ++iter;
  }
  normalize();
}

Pattern *InstructionPattern::doAnd(const Pattern *b,int4 sa) const

{
  if (b->numDisjoint()>0)
    return b->doAnd(this,-sa);

  const CombinePattern *b2 = dynamic_cast<const CombinePattern *>(b);
  if (b2 != (const CombinePattern *)0)
    return b->doAnd(this,-sa);

  const ContextPattern *b3 = dynamic_cast<const ContextPattern *>(b);
  if (b3 != (const ContextPattern *)0) {
    InstructionPattern *newpat = (InstructionPattern *)simplifyClone();
    if (sa < 0)
      newpat->shiftInstruction(-sa);
    return new CombinePattern((ContextPattern *)b3->simplifyClone(),newpat);
  }
  const InstructionPattern *b4 = (const InstructionPattern *)b;

  PatternBlock *respattern;
  if (sa < 0) {
    PatternBlock *a = maskvalue->clone();
    a->shift(-sa);
    respattern = a->intersect(b4->maskvalue);
    delete a;
  }
  else {
    PatternBlock *c = b4->maskvalue->clone();
    c->shift(sa);
    respattern = maskvalue->intersect(c);
    delete c;
  }
  return new InstructionPattern(respattern);
}

Pattern *InstructionPattern::commonSubPattern(const Pattern *b,int4 sa) const

{
  if (b->numDisjoint()>0)
    return b->commonSubPattern(this,-sa);

  const CombinePattern *b2 = dynamic_cast<const CombinePattern *>(b);
  if (b2 != (const CombinePattern *)0)
    return b->commonSubPattern(this,-sa);

  const ContextPattern *b3 = dynamic_cast<const ContextPattern *>(b);
  if (b3 != (const ContextPattern *)0) {
    InstructionPattern *res = new InstructionPattern(true);
    return res;
  }
  const InstructionPattern *b4 = (const InstructionPattern *)b;
  
  PatternBlock *respattern;
  if (sa < 0) {
    PatternBlock *a = maskvalue->clone();
    a->shift(-sa);
    respattern = a->commonSubPattern(b4->maskvalue);
    delete a;
  }
  else {
    PatternBlock *c = b4->maskvalue->clone();
    c->shift(sa);
    respattern = maskvalue->commonSubPattern(c);
    delete c;
  }
  return new InstructionPattern(respattern);
}

Pattern *InstructionPattern::doOr(const Pattern *b,int4 sa) const

{
  if (b->numDisjoint()>0)
    return b->doOr(this,-sa);

  const CombinePattern *b2 = dynamic_cast<const CombinePattern *>(b);
  if (b2 != (const CombinePattern *)0)
    return b->doOr(this,-sa);

  DisjointPattern *res1,*res2;
  res1 = (DisjointPattern *)simplifyClone();
  res2 = (DisjointPattern *)b->simplifyClone();
  if (sa < 0)
    res1->shiftInstruction(-sa);
  else
    res2->shiftInstruction(sa);
  return new OrPattern(res1,res2);
}

void InstructionPattern::saveXml(ostream &s) const

{
  s << "<instruct_pat>\n";
  maskvalue->saveXml(s);
  s << "</instruct_pat>\n";
}

void InstructionPattern::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  maskvalue = new PatternBlock(true);
  maskvalue->restoreXml(*iter);
}

Pattern *ContextPattern::doOr(const Pattern *b,int4 sa) const

{
  const ContextPattern *b2 = dynamic_cast<const ContextPattern *>(b);
  if (b2 == (const ContextPattern *)0)
    return b->doOr(this,-sa);

  return new OrPattern((DisjointPattern *)simplifyClone(),(DisjointPattern *)b2->simplifyClone());
}

Pattern *ContextPattern::doAnd(const Pattern *b,int4 sa) const

{
  const ContextPattern *b2 = dynamic_cast<const ContextPattern *>(b);
  if (b2 == (const ContextPattern *)0)
    return b->doAnd(this,-sa);

  PatternBlock *resblock = maskvalue->intersect(b2->maskvalue);
  return new ContextPattern(resblock);
}

Pattern *ContextPattern::commonSubPattern(const Pattern *b,int4 sa) const

{
  const ContextPattern *b2 = dynamic_cast<const ContextPattern *>(b);
  if (b2 == (const ContextPattern *)0)
    return b->commonSubPattern(this,-sa);

  PatternBlock *resblock = maskvalue->commonSubPattern(b2->maskvalue);
  return new ContextPattern(resblock);
}

void ContextPattern::saveXml(ostream &s) const

{
  s << "<context_pat>\n";
  maskvalue->saveXml(s);
  s << "</context_pat>\n";
}

void ContextPattern::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  maskvalue = new PatternBlock(true);
  maskvalue->restoreXml(*iter);
}

CombinePattern::~CombinePattern(void)

{
  if (context != (ContextPattern *)0)
    delete context;
  if (instr != (InstructionPattern *)0)
    delete instr;
}

bool CombinePattern::isMatch(ParserWalker &walker) const

{
  if (!instr->isMatch(walker)) return false;
  if (!context->isMatch(walker)) return false;
  return true;
}

bool CombinePattern::alwaysTrue(void) const

{
  return (context->alwaysTrue() && instr->alwaysTrue());
}

bool CombinePattern::alwaysFalse(void) const

{
  return (context->alwaysFalse() || instr->alwaysFalse());
}

Pattern *CombinePattern::doAnd(const Pattern *b,int4 sa) const

{
  CombinePattern *tmp;
  
  if (b->numDisjoint() != 0)
    return b->doAnd(this,-sa);

  const CombinePattern *b2 = dynamic_cast<const CombinePattern *>(b);
  if (b2 != (CombinePattern *)0) {
    ContextPattern *c = (ContextPattern *)context->doAnd(b2->context,0);
    InstructionPattern *i = (InstructionPattern *)instr->doAnd(b2->instr,sa);
    tmp = new CombinePattern(c,i);
  }
  else {
    const InstructionPattern *b3 = dynamic_cast<const InstructionPattern *>(b);
    if (b3 != (const InstructionPattern *)0) {
      InstructionPattern *i = (InstructionPattern *)instr->doAnd(b3,sa);
      tmp = new CombinePattern((ContextPattern *)context->simplifyClone(),i);
    }
    else {			// Must be a ContextPattern
      ContextPattern *c = (ContextPattern *)context->doAnd(b,0);
      InstructionPattern *newpat = (InstructionPattern *) instr->simplifyClone();
      if (sa < 0)
	newpat->shiftInstruction(-sa);
      tmp = new CombinePattern(c,newpat);
    }
  }
  return tmp;
}

Pattern *CombinePattern::commonSubPattern(const Pattern *b,int4 sa) const

{
  Pattern *tmp;

  if (b->numDisjoint() != 0)
    return b->commonSubPattern(this,-sa);

  const CombinePattern *b2 = dynamic_cast<const CombinePattern *>(b);
  if (b2 != (CombinePattern *)0) {
    ContextPattern *c = (ContextPattern *)context->commonSubPattern(b2->context,0);
    InstructionPattern *i = (InstructionPattern *)instr->commonSubPattern(b2->instr,sa);
    tmp = new CombinePattern(c,i);
  }
  else {
    const InstructionPattern *b3 = dynamic_cast<const InstructionPattern *>(b);
    if (b3 != (const InstructionPattern *)0)
      tmp = instr->commonSubPattern(b3,sa);
    else			// Must be a ContextPattern
      tmp = context->commonSubPattern(b,0);
  }
  return tmp;
}

Pattern *CombinePattern::doOr(const Pattern *b,int4 sa) const

{
  if (b->numDisjoint() != 0)
    return b->doOr(this,-sa);

  DisjointPattern *res1 = (DisjointPattern *)simplifyClone();
  DisjointPattern *res2 = (DisjointPattern *)b->simplifyClone();
  if (sa < 0)
    res1->shiftInstruction(-sa);
  else
    res2->shiftInstruction(sa);
  OrPattern *tmp = new OrPattern(res1,res2);
  return tmp;
}

Pattern *CombinePattern::simplifyClone(void) const

{				// We should only have to think at "our" level
  if (context->alwaysTrue())
    return instr->simplifyClone();
  if (instr->alwaysTrue())
    return context->simplifyClone();
  if (context->alwaysFalse()||instr->alwaysFalse())
    return new InstructionPattern(false);
  return new CombinePattern((ContextPattern *)context->simplifyClone(),
			    (InstructionPattern *)instr->simplifyClone());
}

void CombinePattern::saveXml(ostream &s) const

{
  s << "<combine_pat>\n";
  context->saveXml(s);
  instr->saveXml(s);
  s << "</combine_pat>\n";
}

void CombinePattern::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  context = new ContextPattern();
  context->restoreXml(*iter);
  ++iter;
  instr = new InstructionPattern();
  instr->restoreXml(*iter);
}

OrPattern::OrPattern(DisjointPattern *a,DisjointPattern *b)

{
  orlist.push_back(a);
  orlist.push_back(b);
}

OrPattern::OrPattern(const vector<DisjointPattern *> &list)

{
  vector<DisjointPattern *>::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter)
    orlist.push_back(*iter);
}

OrPattern::~OrPattern(void)

{
  vector<DisjointPattern *>::iterator iter;

  for(iter=orlist.begin();iter!=orlist.end();++iter)
    delete *iter;
}

void OrPattern::shiftInstruction(int4 sa)

{
  vector<DisjointPattern *>::iterator iter;

  for(iter=orlist.begin();iter!=orlist.end();++iter)
    (*iter)->shiftInstruction(sa);
}

bool OrPattern::isMatch(ParserWalker &walker) const

{
  for(int4 i=0;i<orlist.size();++i)
    if (orlist[i]->isMatch(walker))
      return true;
  return false;
}

bool OrPattern::alwaysTrue(void) const

{				// This isn't quite right because different branches
				// may cover the entire gamut
  vector<DisjointPattern *>::const_iterator iter;

  for(iter=orlist.begin();iter!=orlist.end();++iter)
    if ((*iter)->alwaysTrue()) return true;
  return false;
}

bool OrPattern::alwaysFalse(void) const

{
  vector<DisjointPattern *>::const_iterator iter;

  for(iter=orlist.begin();iter!=orlist.end();++iter)
    if (!(*iter)->alwaysFalse()) return false;
  return true;
}

bool OrPattern::alwaysInstructionTrue(void) const

{
  vector<DisjointPattern *>::const_iterator iter;

  for(iter=orlist.begin();iter!=orlist.end();++iter)
    if (!(*iter)->alwaysInstructionTrue()) return false;
  return true;
}

Pattern *OrPattern::doAnd(const Pattern *b,int4 sa) const

{
  const OrPattern *b2 = dynamic_cast<const OrPattern *>(b);
  vector<DisjointPattern *> newlist;
  vector<DisjointPattern *>::const_iterator iter,iter2;
  DisjointPattern *tmp;
  OrPattern *tmpor;

  if (b2 == (const OrPattern *)0) {
    for(iter=orlist.begin();iter!=orlist.end();++iter) {
      tmp = (DisjointPattern *)(*iter)->doAnd(b,sa);
      newlist.push_back(tmp);
    }
  }
  else {
    for(iter=orlist.begin();iter!=orlist.end();++iter)
      for(iter2=b2->orlist.begin();iter2!=b2->orlist.end();++iter2) {
	tmp = (DisjointPattern *)(*iter)->doAnd(*iter2,sa);
	newlist.push_back(tmp);
      }
  }
  tmpor = new OrPattern(newlist);
  return tmpor;
}

Pattern *OrPattern::commonSubPattern(const Pattern *b,int4 sa) const

{
  vector<DisjointPattern *>::const_iterator iter;
  Pattern *res,*next;

  iter = orlist.begin();
  res = (*iter)->commonSubPattern(b,sa);
  iter++;

  if (sa > 0)
    sa = 0;
  while(iter!=orlist.end()) {
    next = (*iter)->commonSubPattern(res,sa);
    delete res;
    res = next;
    ++iter;
  }
  return res;
}

Pattern *OrPattern::doOr(const Pattern *b,int4 sa) const

{
  const OrPattern *b2 = dynamic_cast<const OrPattern *>(b);
  vector<DisjointPattern *> newlist;
  vector<DisjointPattern *>::const_iterator iter;

  for(iter=orlist.begin();iter!=orlist.end();++iter)
    newlist.push_back((DisjointPattern *)(*iter)->simplifyClone());
  if (sa < 0)
    for(iter=orlist.begin();iter!=orlist.end();++iter)
      (*iter)->shiftInstruction(-sa);

  if (b2 == (const OrPattern *)0)
    newlist.push_back((DisjointPattern *)b->simplifyClone());
  else {
    for(iter=b2->orlist.begin();iter!=b2->orlist.end();++iter)
      newlist.push_back((DisjointPattern *)(*iter)->simplifyClone());
  }
  if (sa > 0)
    for(int4 i=0;i<newlist.size();++i)
      newlist[i]->shiftInstruction(sa);

  OrPattern *tmpor = new OrPattern(newlist);
  return tmpor;
}

Pattern *OrPattern::simplifyClone(void) const

{				// Look for alwaysTrue eliminate alwaysFalse
  vector<DisjointPattern *>::const_iterator iter;

  for(iter=orlist.begin();iter!=orlist.end();++iter) // Look for alwaysTrue
    if ((*iter)->alwaysTrue())
      return new InstructionPattern(true);

  vector<DisjointPattern *> newlist;
  for(iter=orlist.begin();iter!=orlist.end();++iter) // Look for alwaysFalse
    if (!(*iter)->alwaysFalse())
      newlist.push_back((DisjointPattern *)(*iter)->simplifyClone());
  
  if (newlist.empty())
    return new InstructionPattern(false);
  else if (newlist.size() == 1)
    return newlist[0];
  return new OrPattern(newlist);
}

void OrPattern::saveXml(ostream &s) const

{
  s << "<or_pat>\n";
  for(int4 i=0;i<orlist.size();++i)
    orlist[i]->saveXml(s);
  s << "</or_pat>\n";
}

void OrPattern::restoreXml(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  while(iter != list.end()) {
    DisjointPattern *pat = DisjointPattern::restoreDisjoint(*iter);
    orlist.push_back(pat);
    ++iter;
  }
}

} // End namespace ghidra
