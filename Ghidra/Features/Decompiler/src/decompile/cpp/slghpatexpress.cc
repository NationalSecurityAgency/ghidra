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
#include "slghpatexpress.hh"
#include "sleighbase.hh"

namespace ghidra {

int4 TokenPattern::resolveTokens(const TokenPattern &tok1,const TokenPattern &tok2)

{				// Use the token lists to decide how the two patterns
				// should be aligned relative to each other
				// return how much -tok2- needs to be shifted
				// and set the resulting tokenlist and ellipses
  bool reversedirection = false;
  leftellipsis = false;
  rightellipsis = false;
  int4 ressa = 0;
  int4 minsize = tok1.toklist.size() < tok2.toklist.size() ? tok1.toklist.size() : tok2.toklist.size();
  if (minsize == 0) {
				// Check if pattern doesn't care about tokens
    if ((tok1.toklist.size()==0)&&(tok1.leftellipsis==false)&&(tok1.rightellipsis==false)) {
      toklist = tok2.toklist;
      leftellipsis = tok2.leftellipsis;
      rightellipsis = tok2.rightellipsis;
      return 0;
    }
    else if ((tok2.toklist.size()==0)&&(tok2.leftellipsis==false)&&(tok2.rightellipsis==false)) {
      toklist = tok1.toklist;
      leftellipsis = tok1.leftellipsis;
      rightellipsis = tok1.rightellipsis;
      return 0;
    }
				// If one of the ellipses is true then the pattern
				// still cares about tokens even though none are
				// specified
  }
  
  if (tok1.leftellipsis) {
    reversedirection = true;
    if (tok2.rightellipsis)
      throw SleighError("Right/left ellipsis");
    else if (tok2.leftellipsis)
      leftellipsis = true;
    else if (tok1.toklist.size() != minsize) {
      ostringstream msg;
      msg << "Mismatched pattern sizes -- " << dec << tok1.toklist.size()
	  << " != "
	  << dec << minsize;
      throw SleighError(msg.str());
    }
    else if (tok1.toklist.size()==tok2.toklist.size())
      throw SleighError("Pattern size cannot vary (missing '...'?)");
  }
  else if (tok1.rightellipsis) {
    if (tok2.leftellipsis)
      throw SleighError("Left/right ellipsis");
    else if (tok2.rightellipsis)
      rightellipsis = true;
    else if (tok1.toklist.size() != minsize) {
      ostringstream msg;
      msg << "Mismatched pattern sizes -- " << dec << tok1.toklist.size()
	  << " != "
	  << dec << minsize;
      throw SleighError(msg.str());
    }
    else if (tok1.toklist.size()==tok2.toklist.size())
      throw SleighError("Pattern size cannot vary (missing '...'?)");
  }
  else {
    if (tok2.leftellipsis) {
      reversedirection = true;
      if (tok2.toklist.size() != minsize) {
	ostringstream msg;
	msg << "Mismatched pattern sizes -- " << dec << tok2.toklist.size()
	    << " != "
	    << dec << minsize;
	throw SleighError(msg.str());
      }
      else if (tok1.toklist.size()==tok2.toklist.size())
	throw SleighError("Pattern size cannot vary (missing '...'?)");
    }
    else if (tok2.rightellipsis) {
      if (tok2.toklist.size() != minsize) {
	ostringstream msg;
	msg << "Mismatched pattern sizes -- " << dec << tok2.toklist.size()
	    << " != "
	    << dec << minsize;
	throw SleighError(msg.str());
      }
      else if (tok1.toklist.size()==tok2.toklist.size())
	throw SleighError("Pattern size cannot vary (missing '...'?)");
    }
    else {
      if (tok2.toklist.size() != tok1.toklist.size()) {
	ostringstream msg;
	msg << "Mismatched pattern sizes -- " << dec << tok2.toklist.size()
	    << " != "
	    << dec << tok1.toklist.size();
	throw SleighError(msg.str());
      }
    }
  }
  if (reversedirection) {
    for(int4 i=0;i<minsize;++i)
      if (tok1.toklist[tok1.toklist.size()-1-i] != tok2.toklist[tok2.toklist.size()-1-i]) {

	ostringstream msg;
	msg << "Mismatched tokens when combining patterns -- "
	    << dec << tok1.toklist[tok1.toklist.size()-1-i]
	    << " != "
	    << dec << tok2.toklist[tok2.toklist.size()-1-i];
	throw SleighError(msg.str());
      }
    if (tok1.toklist.size() <= tok2.toklist.size())
      for(int4 i=minsize;i<tok2.toklist.size();++i)
	ressa += tok2.toklist[tok2.toklist.size()-1-i]->getSize();
    else
      for(int4 i=minsize;i<tok1.toklist.size();++i)
	ressa += tok1.toklist[tok1.toklist.size()-1-i]->getSize();
    if (tok1.toklist.size() < tok2.toklist.size())
      ressa = -ressa;
  }
  else {
    for(int4 i=0;i<minsize;++i)
      if (tok1.toklist[i] != tok2.toklist[i]) {
		ostringstream msg;
	msg << "Mismatched tokens when combining patterns -- "
	    << dec << tok1.toklist[i]
	    << " != "
	    << dec << tok2.toklist[i];
	throw SleighError(msg.str());
      }
  }
				// Save the results into -this-
  if (tok1.toklist.size() <= tok2.toklist.size())
    toklist = tok2.toklist;
  else
    toklist = tok1.toklist;
  return ressa;
}

PatternBlock *TokenPattern::buildSingle(int4 startbit,int4 endbit,uintm byteval)

{				// Create a mask/value pattern within a single word
				// The field is given by the bitrange [startbit,endbit]
				// bit 0 is the MOST sig bit of the word
				// use the least sig bits of byteval to fill in
				// the field's value
  uintm mask;
  int4 offset = 0;
  int4 size = endbit-startbit+1;
  while(startbit >= 8) {
    offset += 1;
    startbit -= 8;
    endbit -= 8;
  }
  mask = (~((uintm)0)) << (sizeof(uintm)*8-size);
  byteval = (byteval << (sizeof(uintm)*8-size))& mask;
  mask >>= startbit;
  byteval >>= startbit;
  return new PatternBlock(offset,mask,byteval);
}

PatternBlock *TokenPattern::buildBigBlock(int4 size,int4 bitstart,int4 bitend,intb value)

{				// Build pattern block given a bigendian contiguous
				// range of bits and a value for those bits
  int4 tmpstart,startbit,endbit;
  PatternBlock *tmpblock,*block;

  startbit = 8*size - 1 - bitend;
  endbit = 8*size - 1 - bitstart;
  
  block = (PatternBlock *)0;
  while(endbit >= startbit) {
    tmpstart = endbit - (endbit & 7);
    if (tmpstart < startbit)
      tmpstart = startbit;
    tmpblock = buildSingle(tmpstart,endbit,(uintm)value);
    if (block == (PatternBlock *)0)
      block = tmpblock;
    else {
      PatternBlock *newblock = block->intersect(tmpblock);
      delete block;
      delete tmpblock;
      block = newblock;
    }
    value >>= (endbit-tmpstart+1);
    endbit = tmpstart - 1;
  }
  return block;
}

PatternBlock *TokenPattern::buildLittleBlock(int4 size,int4 bitstart,int4 bitend,intb value)

{				// Build pattern block given a littleendian contiguous
				// range of bits and a value for those bits
  PatternBlock *tmpblock,*block;
  int4 startbit,endbit;

  block = (PatternBlock *)0;

  // we need to convert a bit range specified on a little endian token where the
  // bit indices label the least sig bit as 0 into a bit range on big endian bytes
  // where the indices label the most sig bit as 0.  The reversal due to
  // little->big endian cancels part of the reversal due to least->most sig bit
  // labelling, but not on the lower 3 bits.  So the transform becomes
  // leave the upper bits the same, but transform the lower 3-bit value x into 7-x.

  startbit = (bitstart/8) * 8;	// Get the high-order portion of little/LSB labelling
  endbit = (bitend/8) * 8;
  bitend = bitend % 8;		// Get the low-order portion of little/LSB labelling
  bitstart = bitstart % 8;

  if (startbit == endbit) {
    startbit += 7 - bitend;
    endbit += 7 - bitstart;
    block = buildSingle(startbit,endbit,(uintm)value);
  }
  else {
    block = buildSingle(startbit,startbit+(7-bitstart),(uintm)value);
    value >>= (8-bitstart);	// Cut off bits we just encoded
    startbit += 8;
    while(startbit != endbit) {
      tmpblock = buildSingle(startbit,startbit+7,(uintm)value);
      if (block == (PatternBlock *)0)
	block = tmpblock;
      else {
	PatternBlock *newblock = block->intersect(tmpblock);
	delete block;
	delete tmpblock;
	block = newblock;
      }
      value >>= 8;
      startbit += 8;
    }
    tmpblock = buildSingle(endbit+(7-bitend),endbit+7,(uintm)value);
    if (block == (PatternBlock *)0)
      block = tmpblock;
    else {
      PatternBlock *newblock = block->intersect(tmpblock);
      delete block;
      delete tmpblock;
      block = newblock;
    }
  }
  return block;
}

TokenPattern::TokenPattern(void)

{
  leftellipsis = false;
  rightellipsis = false;
  pattern = new InstructionPattern(true);
}

TokenPattern::TokenPattern(bool tf)

{				// TRUE or FALSE pattern
  leftellipsis = false;
  rightellipsis = false;
  pattern = new InstructionPattern(tf);
}
  
TokenPattern::TokenPattern(Token *tok)

{
  leftellipsis = false;
  rightellipsis = false;
  pattern = new InstructionPattern(true);
  toklist.push_back(tok);
}

TokenPattern::TokenPattern(Token *tok,intb value,int4 bitstart,int4 bitend)

{				// A basic instruction pattern

  toklist.push_back(tok);
  leftellipsis = false;
  rightellipsis = false;
  PatternBlock *block;

  if (tok->isBigEndian())
    block = buildBigBlock(tok->getSize(),bitstart,bitend,value);
  else
    block = buildLittleBlock(tok->getSize(),bitstart,bitend,value);
  pattern = new InstructionPattern(block);
}

TokenPattern::TokenPattern(intb value,int4 startbit,int4 endbit)

{				// A basic context pattern
  leftellipsis = false;
  rightellipsis = false;
  PatternBlock *block;
  int4 size = (endbit/8) + 1;

  block = buildBigBlock(size,size*8-1-endbit,size*8-1-startbit,value);
  pattern = new ContextPattern(block);
}

TokenPattern::TokenPattern(const TokenPattern &tokpat)

{
  pattern = tokpat.pattern->simplifyClone();
  toklist = tokpat.toklist;
  leftellipsis = tokpat.leftellipsis;
  rightellipsis = tokpat.rightellipsis;
}

const TokenPattern &TokenPattern::operator=(const TokenPattern &tokpat)

{
  delete pattern;

  pattern = tokpat.pattern->simplifyClone();
  toklist = tokpat.toklist;
  leftellipsis = tokpat.leftellipsis;
  rightellipsis = tokpat.rightellipsis;
  return *this;
}

TokenPattern TokenPattern::doAnd(const TokenPattern &tokpat) const

{				// Return -this- AND tokpat
  TokenPattern res((Pattern *)0);
  int4 sa = res.resolveTokens(*this,tokpat);

  res.pattern = pattern->doAnd(tokpat.pattern,sa);
  return res;
}

TokenPattern TokenPattern::doOr(const TokenPattern &tokpat) const

{				// Return -this- OR tokpat
  TokenPattern res((Pattern *)0);
  int4 sa = res.resolveTokens(*this,tokpat);

  res.pattern = pattern->doOr(tokpat.pattern,sa);
  return res;
}

TokenPattern TokenPattern::doCat(const TokenPattern &tokpat) const

{				// Return Concatenation of -this- and -tokpat-
  TokenPattern res((Pattern *)0);
  int4 sa;

  res.leftellipsis = leftellipsis;
  res.rightellipsis = rightellipsis;
  res.toklist = toklist;
  if (rightellipsis||tokpat.leftellipsis) { // Check for interior ellipsis
    if (rightellipsis) {
      if (!tokpat.alwaysInstructionTrue())
	throw SleighError("Interior ellipsis in pattern");
    }
    if (tokpat.leftellipsis) {
      if (!alwaysInstructionTrue())
	throw SleighError("Interior ellipsis in pattern");
      res.leftellipsis = true;
    }
    sa = -1;
  }
  else {
    sa = 0;
    vector<Token *>::const_iterator iter;

    for(iter=toklist.begin();iter!=toklist.end();++iter)
      sa += (*iter)->getSize();
    for(iter=tokpat.toklist.begin();iter!=tokpat.toklist.end();++iter)
      res.toklist.push_back(*iter);
    res.rightellipsis = tokpat.rightellipsis;
  }
  if (res.rightellipsis && res.leftellipsis)
    throw SleighError("Double ellipsis in pattern");
  if (sa < 0)
    res.pattern = pattern->doAnd(tokpat.pattern,0);
  else
    res.pattern = pattern->doAnd(tokpat.pattern,sa);
  return res;
}

TokenPattern TokenPattern::commonSubPattern(const TokenPattern &tokpat) const

{				// Construct pattern that matches anything
				// that matches either -this- or -tokpat-
  TokenPattern patres((Pattern *)0); // Empty shell
  int4 i;
  bool reversedirection = false;

  if (leftellipsis||tokpat.leftellipsis) {
    if (rightellipsis||tokpat.rightellipsis)
      throw SleighError("Right/left ellipsis in commonSubPattern");
    reversedirection = true;
  }

				// Find common subset of tokens and ellipses
  patres.leftellipsis = leftellipsis || tokpat.leftellipsis;
  patres.rightellipsis = rightellipsis || tokpat.rightellipsis;
  int4 minnum = toklist.size();
  int4 maxnum = tokpat.toklist.size();
  if (maxnum < minnum) {
    int4 tmp = minnum;
    minnum = maxnum;
    maxnum = tmp;
  }
  if (reversedirection) {
    for(i=0;i<minnum;++i) {
      Token *tok = toklist[toklist.size()-1-i];
      if (tok == tokpat.toklist[tokpat.toklist.size()-1-i])
	patres.toklist.insert(patres.toklist.begin(),tok);
      else
	break;
    }
    if (i<maxnum)
      patres.leftellipsis = true;
  }
  else {
    for(i=0;i<minnum;++i) {
      Token *tok = toklist[i];
      if (tok == tokpat.toklist[i])
	patres.toklist.push_back(tok);
      else
	break;
    }
    if (i<maxnum)
      patres.rightellipsis = true;
  }
  
  patres.pattern = pattern->commonSubPattern(tokpat.pattern,0);
  return patres;
}

int4 TokenPattern::getMinimumLength(void) const

{				// Add up length of concatenated tokens
  int4 length = 0;
  for(int4 i=0;i<toklist.size();++i)
    length += toklist[i]->getSize();
  return length;
}

void PatternExpression::release(PatternExpression *p)

{
  p->refcount -= 1;
  if (p->refcount <= 0)
    delete p;
}

PatternExpression *PatternExpression::restoreExpression(const Element *el,Translate *trans)

{
  PatternExpression *res;
  const string &nm(el->getName());

  if (nm == "tokenfield")
    res = new TokenField();
  else if (nm == "contextfield")
    res = new ContextField();
  else if (nm == "intb")
    res = new ConstantValue();
  else if (nm == "operand_exp")
    res = new OperandValue();
  else if (nm == "start_exp")
    res = new StartInstructionValue();
  else if (nm == "end_exp")
    res = new EndInstructionValue();
  else if (nm == "plus_exp")
    res = new PlusExpression();
  else if (nm == "sub_exp")
    res = new SubExpression();
  else if (nm == "mult_exp")
    res = new MultExpression();
  else if (nm == "lshift_exp")
    res = new LeftShiftExpression();
  else if (nm == "rshift_exp")
    res = new RightShiftExpression();
  else if (nm == "and_exp")
    res = new AndExpression();
  else if (nm == "or_exp")
    res = new OrExpression();
  else if (nm == "xor_exp")
    res = new XorExpression();
  else if (nm == "div_exp")
    res = new DivExpression();
  else if (nm == "minus_exp")
    res = new MinusExpression();
  else if (nm == "not_exp")
    res = new NotExpression();
  else
    return (PatternExpression *)0;

  res->restoreXml(el,trans);
  return res;
}

static intb getInstructionBytes(ParserWalker &walker,int4 bytestart,int4 byteend,bool bigendian)

{				// Build a intb from the instruction bytes
  intb res = 0;
  uintm tmp;
  int4 size,tmpsize;

  size = byteend-bytestart+1;
  tmpsize = size;
  while(tmpsize >= sizeof(uintm)) {
    tmp = walker.getInstructionBytes(bytestart,sizeof(uintm));
    res <<= 8*sizeof(uintm);
    res |= tmp;
    bytestart += sizeof(uintm);
    tmpsize -= sizeof(uintm);
  }
  if (tmpsize > 0) {
    tmp = walker.getInstructionBytes(bytestart,tmpsize);
    res <<= 8*tmpsize;
    res |= tmp;
  }
  if (!bigendian)
    byte_swap(res,size);
  return res;
}

static intb getContextBytes(ParserWalker &walker,int4 bytestart,int4 byteend)

{				// Build a intb from the context bytes
  intb res = 0;
  uintm tmp;
  int4 size;

  size = byteend-bytestart+1;
  while(size >= sizeof(uintm)) {
    tmp = walker.getContextBytes(bytestart,sizeof(uintm));
    res <<= 8*sizeof(uintm);
    res |= tmp;
    bytestart += sizeof(uintm);
    size = byteend-bytestart+1;
  }
  if (size > 0) {
    tmp = walker.getContextBytes(bytestart,size);
    res <<= 8*size;
    res |= tmp;
  }
  return res;
}

TokenField::TokenField(Token *tk,bool s,int4 bstart,int4 bend)

{
  tok = tk;
  bigendian = tok->isBigEndian();
  signbit = s;
  bitstart = bstart;
  bitend = bend;
  if (tk->isBigEndian()) {
    byteend = (tk->getSize()*8 - bitstart - 1)/8;
    bytestart = (tk->getSize()*8 - bitend - 1)/8;
  }
  else {
    bytestart = bitstart/8;
    byteend = bitend/8;
  }
  shift = bitstart % 8;
}

intb TokenField::getValue(ParserWalker &walker) const

{				// Construct value given specific instruction stream
  intb res = getInstructionBytes(walker,bytestart,byteend,bigendian);
  
  res >>= shift;
  if (signbit)
    res = sign_extend(res,bitend-bitstart);
  else
    res = zero_extend(res,bitend-bitstart);
  return res;
}

TokenPattern TokenField::genPattern(intb val) const

{				// Generate corresponding pattern if the
				// value is forced to be val
  return TokenPattern(tok,val,bitstart,bitend);
}

void TokenField::saveXml(ostream &s) const

{
  s << "<tokenfield";
  s << " bigendian=\"";
  if (bigendian)
    s << "true\"";
  else
    s << "false\"";
  s << " signbit=\"";
  if (signbit)
    s << "true\"";
  else
    s << "false\"";
  s << " bitstart=\"" << dec << bitstart << "\"";
  s << " bitend=\"" << bitend << "\"";
  s << " bytestart=\"" << bytestart << "\"";
  s << " byteend=\"" << byteend << "\"";
  s << " shift=\"" << shift << "\"/>\n";
}

void TokenField::restoreXml(const Element *el,Translate *trans)

{
  tok = (Token *)0;
  bigendian = xml_readbool(el->getAttributeValue("bigendian"));
  signbit = xml_readbool(el->getAttributeValue("signbit"));
  {
    istringstream s(el->getAttributeValue("bitstart"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> bitstart;
  }
  {
    istringstream s(el->getAttributeValue("bitend"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> bitend;
  }
  {
    istringstream s(el->getAttributeValue("bytestart"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> bytestart;
  }
  {
    istringstream s(el->getAttributeValue("byteend"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> byteend;
  }
  {
    istringstream s(el->getAttributeValue("shift"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> shift;
  }
}

ContextField::ContextField(bool s,int4 sbit,int4 ebit)

{
  signbit = s;
  startbit = sbit;
  endbit = ebit;
  startbyte = startbit/8;
  endbyte = endbit/8;
  shift = 7 - (endbit%8);
}

intb ContextField::getValue(ParserWalker &walker) const

{
  intb res = getContextBytes(walker,startbyte,endbyte);
  res >>= shift;
  if (signbit)
    res = sign_extend(res,endbit-startbit);
  else
    res = zero_extend(res,endbit-startbit);
  return res;
}

TokenPattern ContextField::genPattern(intb val) const

{
  return TokenPattern(val,startbit,endbit);
}

void ContextField::saveXml(ostream &s) const

{
  s << "<contextfield";
  s << " signbit=\"";
  if (signbit)
    s << "true\"";
  else
    s << "false\"";
  s << " startbit=\"" << dec << startbit << "\"";
  s << " endbit=\"" << endbit << "\"";
  s << " startbyte=\"" << startbyte << "\"";
  s << " endbyte=\"" << endbyte << "\"";
  s << " shift=\"" << shift << "\"/>\n";
}

void ContextField::restoreXml(const Element *el,Translate *trans)

{
  signbit = xml_readbool(el->getAttributeValue("signbit"));
  {
    istringstream s(el->getAttributeValue("startbit"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> startbit;
  }
  {
    istringstream s(el->getAttributeValue("endbit"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> endbit;
  }
  {
    istringstream s(el->getAttributeValue("startbyte"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> startbyte;
  }
  {
    istringstream s(el->getAttributeValue("endbyte"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> endbyte;
  }
  {
    istringstream s(el->getAttributeValue("shift"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> shift;
  }
}

void ConstantValue::saveXml(ostream &s) const

{
  s << "<intb val=\"" << dec << val << "\"/>\n";
}

void ConstantValue::restoreXml(const Element *el,Translate *trans)

{
  istringstream s(el->getAttributeValue("val"));
  s.unsetf(ios::dec | ios::hex | ios::oct);
  s >> val;
}

TokenPattern OperandValue::genPattern(intb val) const

{
  // In general an operand cannot be interpreted as any sort
  // of static constraint in an equation, and if it is being
  // defined by the equation, it should be on the left hand side.
  // If the operand has a defining expression already, use
  // of the operand in the equation makes sense, its defining
  // expression would become a subexpression in the full
  // expression. However, since this can be accomplished
  // by explicitly copying the subexpression into the full
  // expression, we don't support operands as placeholders.
  throw SleighError("Operand used in pattern expression");
}

intb OperandValue::minValue(void) const

{
  throw SleighError("Operand used in pattern expression");
}

intb OperandValue::maxValue(void) const

{
  throw SleighError("Operand used in pattern expression");
}

intb OperandValue::getValue(ParserWalker &walker) const

{				// Get the value of an operand when it is used in
				// an expression. 
  OperandSymbol *sym = ct->getOperand(index);
  PatternExpression *patexp = sym->getDefiningExpression();
  if (patexp == (PatternExpression *)0) {
    TripleSymbol *defsym = sym->getDefiningSymbol();
    if (defsym != (TripleSymbol *)0)
      patexp = defsym->getPatternExpression();
    if (patexp == (PatternExpression *)0)
      return 0;
  }
  ConstructState tempstate;
  ParserWalker newwalker(walker.getParserContext());
  newwalker.setOutOfBandState(ct,index,&tempstate,walker);
  intb res = patexp->getValue(newwalker);
  return res;
}

intb OperandValue::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  OperandSymbol *sym = ct->getOperand(index);
  return sym->getDefiningExpression()->getSubValue(replace,listpos);
}

bool OperandValue::isConstructorRelative(void) const

{
  OperandSymbol *sym = ct->getOperand(index);
  return (sym->getOffsetBase()==-1);
}

const string &OperandValue::getName(void) const

{
  OperandSymbol *sym = ct->getOperand(index);
  return sym->getName();
}

void OperandValue::saveXml(ostream &s) const

{
  s << "<operand_exp";
  s << " index=\"" << dec << index << "\"";
  s << " table=\"0x" << hex << ct->getParent()->getId() << "\"";
  s << " ct=\"0x" << ct->getId() << "\"/>\n"; // Save id of our constructor
}

void OperandValue::restoreXml(const Element *el,Translate *trans)

{
  uintm ctid,tabid;
  {
    istringstream s(el->getAttributeValue("index"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> index;
  }
  {
    istringstream s(el->getAttributeValue("table"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> tabid;
  }
  {
    istringstream s(el->getAttributeValue("ct"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> ctid;
  }
  SleighBase *sleigh = (SleighBase *)trans;
  SubtableSymbol *tab = dynamic_cast<SubtableSymbol *>(sleigh->findSymbol(tabid));
  ct = tab->getConstructor(ctid);
}

BinaryExpression::BinaryExpression(PatternExpression *l,PatternExpression *r)

{
  (left=l)->layClaim();
  (right=r)->layClaim();
}

BinaryExpression::~BinaryExpression(void)

{				// Delete only non-pattern values
  if (left != (PatternExpression *)0)
    PatternExpression::release(left);
  if (right != (PatternExpression *)0)
    PatternExpression::release(right);
}

void BinaryExpression::saveXml(ostream &s) const

{				// Outer tag is generated by derived classes
  left->saveXml(s);
  right->saveXml(s);
}

void BinaryExpression::restoreXml(const Element *el,Translate *trans)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  left = PatternExpression::restoreExpression(*iter,trans);
  ++iter;
  right = PatternExpression::restoreExpression(*iter,trans);
  left->layClaim();
  right->layClaim();
}

UnaryExpression::UnaryExpression(PatternExpression *u)

{
  (unary=u)->layClaim();
}

UnaryExpression::~UnaryExpression(void)

{				// Delete only non-pattern values
  if (unary != (PatternExpression *)0)
    PatternExpression::release(unary);
}

void UnaryExpression::saveXml(ostream &s) const

{				// Outer tag is generated by derived classes
  unary->saveXml(s);
}

void UnaryExpression::restoreXml(const Element *el,Translate *trans)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  unary = PatternExpression::restoreExpression(*iter,trans);
  unary->layClaim();
}

intb PlusExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval + rightval;
}

intb PlusExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval + rightval;
}

void PlusExpression::saveXml(ostream &s) const

{
  s << "<plus_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</plus_exp>\n";
}

intb SubExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval - rightval;
}

intb SubExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval - rightval;
}

void SubExpression::saveXml(ostream &s) const

{
  s << "<sub_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</sub_exp>\n";
}

intb MultExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval * rightval;
}

intb MultExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval * rightval;
}

void MultExpression::saveXml(ostream &s) const

{
  s << "<mult_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</mult_exp>\n";
}

intb LeftShiftExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval << rightval;
}

intb LeftShiftExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval << rightval;
}

void LeftShiftExpression::saveXml(ostream &s) const

{
  s << "<lshift_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</lshift_exp>\n";
}

intb RightShiftExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval >> rightval;
}

intb RightShiftExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval >> rightval;
}

void RightShiftExpression::saveXml(ostream &s) const

{
  s << "<rshift_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</rshift_exp>\n";
}

intb AndExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval & rightval;
}

intb AndExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval & rightval;
}

void AndExpression::saveXml(ostream &s) const

{
  s << "<and_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</and_exp>\n";
}

intb OrExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval | rightval;
}

intb OrExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval | rightval;
}

void OrExpression::saveXml(ostream &s) const

{
  s << "<or_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</or_exp>\n";
}

intb XorExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval ^ rightval;
}

intb XorExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval ^ rightval;
}

void XorExpression::saveXml(ostream &s) const

{
  s << "<xor_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</xor_exp>\n";
}

intb DivExpression::getValue(ParserWalker &walker) const

{
  intb leftval = getLeft()->getValue(walker);
  intb rightval = getRight()->getValue(walker);
  return leftval / rightval;
}

intb DivExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb leftval = getLeft()->getSubValue(replace,listpos); // Must be left first
  intb rightval = getRight()->getSubValue(replace,listpos);
  return leftval / rightval;
}

void DivExpression::saveXml(ostream &s) const

{
  s << "<div_exp>\n";
  BinaryExpression::saveXml(s);
  s << "</div_exp>\n";
}

intb MinusExpression::getValue(ParserWalker &walker) const

{
  intb val = getUnary()->getValue(walker);
  return -val;
}

intb MinusExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb val = getUnary()->getSubValue(replace,listpos);
  return -val;
}

void MinusExpression::saveXml(ostream &s) const

{
  s << "<minus_exp>\n";
  UnaryExpression::saveXml(s);
  s << "</minus_exp>\n";
}

intb NotExpression::getValue(ParserWalker &walker) const

{
  intb val = getUnary()->getValue(walker);
  return ~val;
}

intb NotExpression::getSubValue(const vector<intb> &replace,int4 &listpos) const

{
  intb val = getUnary()->getSubValue(replace,listpos);
  return ~val;
}

void NotExpression::saveXml(ostream &s) const

{
  s << "<not_exp>\n";
  UnaryExpression::saveXml(s);
  s << "</not_exp>\n";
}

static bool advance_combo(vector<intb> &val,const vector<intb> &min,vector<intb> &max)

{
  int4 i;

  i = 0;
  while(i<val.size()) {
    val[i] += 1;
    if (val[i] <= max[i])	// maximum is inclusive
      return true;
    val[i] = min[i];
    i += 1;
  }
  return false;
}

static TokenPattern buildPattern(PatternValue *lhs,intb lhsval,vector<const PatternValue *> &semval,
				 vector<intb> &val)

{
  TokenPattern respattern = lhs->genPattern(lhsval);

  for(int4 i=0;i<semval.size();++i)
    respattern = respattern.doAnd(semval[i]->genPattern(val[i]));
  return respattern;
}

void PatternEquation::release(PatternEquation *pateq)

{
  pateq->refcount -= 1;
  if (pateq->refcount <= 0)
    delete pateq;
}

void OperandEquation::genPattern(const vector<TokenPattern> &ops) const

{
  resultpattern = ops[index];
}

bool OperandEquation::resolveOperandLeft(OperandResolve &state) const

{
  OperandSymbol *sym = state.operands[ index ];
  if (sym->isOffsetIrrelevant()) {
    sym->offsetbase = -1;
    sym->reloffset = 0;
    return true;
  }
  if (state.base == -2)		// We have no base
    return false;
  sym->offsetbase = state.base;
  sym->reloffset = state.offset;
  state.cur_rightmost = index;
  state.size = 0;		// Distance from right edge
  return true;
}

void OperandEquation::operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const

{
  OperandSymbol *sym = ct->getOperand(index);
  if (!sym->isMarked()) {
    order.push_back(sym);
    sym->setMark();
  }
}

UnconstrainedEquation::UnconstrainedEquation(PatternExpression *p)

{
  (patex=p)->layClaim();
}

UnconstrainedEquation::~UnconstrainedEquation(void)

{
  PatternExpression::release(patex);
}

void UnconstrainedEquation::genPattern(const vector<TokenPattern> &ops) const

{
  resultpattern = patex->genMinPattern(ops);
}

bool UnconstrainedEquation::resolveOperandLeft(OperandResolve &state) const

{
  state.cur_rightmost = -1;
  if (resultpattern.getLeftEllipsis()||resultpattern.getRightEllipsis()) // don't know length
    state.size = -1;
  else
    state.size = resultpattern.getMinimumLength();
  return true;
}

ValExpressEquation::ValExpressEquation(PatternValue *l,PatternExpression *r)

{
  (lhs=l)->layClaim();
  (rhs=r)->layClaim();
}

ValExpressEquation::~ValExpressEquation(void)

{
  PatternExpression::release(lhs);
  PatternExpression::release(rhs);
}

bool ValExpressEquation::resolveOperandLeft(OperandResolve &state) const

{
  state.cur_rightmost = -1;
  if (resultpattern.getLeftEllipsis()||resultpattern.getRightEllipsis()) // don't know length
    state.size = -1;
  else
    state.size = resultpattern.getMinimumLength();
  return true;
}

void EqualEquation::genPattern(const vector<TokenPattern> &ops) const

{
  intb lhsmin = lhs->minValue();
  intb lhsmax = lhs->maxValue();
  vector<const PatternValue *> semval;
  vector<intb> min;
  vector<intb> max;
  vector<intb> cur;
  int4 count=0;

  rhs->listValues(semval);
  rhs->getMinMax(min,max);
  cur = min;

  do {
    intb val = rhs->getSubValue(cur);
    if ((val>=lhsmin)&&(val<=lhsmax)) {
      if (count==0)
	resultpattern = buildPattern(lhs,val,semval,cur);
      else
	resultpattern = resultpattern.doOr(buildPattern(lhs,val,semval,cur));
      count += 1;
    }
  } while(advance_combo(cur,min,max));
  if (count == 0)
    throw SleighError("Equal constraint is impossible to match");
}

void NotEqualEquation::genPattern(const vector<TokenPattern> &ops) const

{
  intb lhsmin = lhs->minValue();
  intb lhsmax = lhs->maxValue();
  vector<const PatternValue *> semval;
  vector<intb> min;
  vector<intb> max;
  vector<intb> cur;
  int4 count=0;

  rhs->listValues(semval);
  rhs->getMinMax(min,max);
  cur = min;

  do {
    intb lhsval;
    intb val = rhs->getSubValue(cur);
    for(lhsval=lhsmin;lhsval<=lhsmax;++lhsval) {
      if (lhsval == val) continue;
      if (count==0)
	resultpattern = buildPattern(lhs,lhsval,semval,cur);
      else
	resultpattern = resultpattern.doOr(buildPattern(lhs,lhsval,semval,cur));
      count += 1;
    }
  } while(advance_combo(cur,min,max));
  if (count == 0)
    throw SleighError("Notequal constraint is impossible to match");
}

void LessEquation::genPattern(const vector<TokenPattern> &ops) const

{
  intb lhsmin = lhs->minValue();
  intb lhsmax = lhs->maxValue();
  vector<const PatternValue *> semval;
  vector<intb> min;
  vector<intb> max;
  vector<intb> cur;
  int4 count=0;

  rhs->listValues(semval);
  rhs->getMinMax(min,max);
  cur = min;

  do {
    intb lhsval;
    intb val = rhs->getSubValue(cur);
    for(lhsval=lhsmin;lhsval<=lhsmax;++lhsval) {
      if (lhsval >= val) continue;
      if (count==0)
	resultpattern = buildPattern(lhs,lhsval,semval,cur);
      else
	resultpattern = resultpattern.doOr(buildPattern(lhs,lhsval,semval,cur));
      count += 1;
    }
  } while(advance_combo(cur,min,max));
  if (count == 0)
    throw SleighError("Less than constraint is impossible to match");
}

void LessEqualEquation::genPattern(const vector<TokenPattern> &ops) const

{
  intb lhsmin = lhs->minValue();
  intb lhsmax = lhs->maxValue();
  vector<const PatternValue *> semval;
  vector<intb> min;
  vector<intb> max;
  vector<intb> cur;
  int4 count=0;

  rhs->listValues(semval);
  rhs->getMinMax(min,max);
  cur = min;

  do {
    intb lhsval;
    intb val = rhs->getSubValue(cur);
    for(lhsval=lhsmin;lhsval<=lhsmax;++lhsval) {
      if (lhsval > val) continue;
      if (count==0)
	resultpattern = buildPattern(lhs,lhsval,semval,cur);
      else
	resultpattern = resultpattern.doOr(buildPattern(lhs,lhsval,semval,cur));
      count += 1;
    }
  } while(advance_combo(cur,min,max));
  if (count == 0)
    throw SleighError("Less than or equal constraint is impossible to match");
}

void GreaterEquation::genPattern(const vector<TokenPattern> &ops) const

{
  intb lhsmin = lhs->minValue();
  intb lhsmax = lhs->maxValue();
  vector<const PatternValue *> semval;
  vector<intb> min;
  vector<intb> max;
  vector<intb> cur;
  int4 count=0;

  rhs->listValues(semval);
  rhs->getMinMax(min,max);
  cur = min;

  do {
    intb lhsval;
    intb val = rhs->getSubValue(cur);
    for(lhsval=lhsmin;lhsval<=lhsmax;++lhsval) {
      if (lhsval <= val) continue;
      if (count==0)
	resultpattern = buildPattern(lhs,lhsval,semval,cur);
      else
	resultpattern = resultpattern.doOr(buildPattern(lhs,lhsval,semval,cur));
      count += 1;
    }
  } while(advance_combo(cur,min,max));
  if (count == 0)
    throw SleighError("Greater than constraint is impossible to match");
}

void GreaterEqualEquation::genPattern(const vector<TokenPattern> &ops) const

{
  intb lhsmin = lhs->minValue();
  intb lhsmax = lhs->maxValue();
  vector<const PatternValue *> semval;
  vector<intb> min;
  vector<intb> max;
  vector<intb> cur;
  int4 count=0;

  rhs->listValues(semval);
  rhs->getMinMax(min,max);
  cur = min;

  do {
    intb lhsval;
    intb val = rhs->getSubValue(cur);
    for(lhsval=lhsmin;lhsval<=lhsmax;++lhsval) {
      if (lhsval < val) continue;
      if (count==0)
	resultpattern = buildPattern(lhs,lhsval,semval,cur);
      else
	resultpattern = resultpattern.doOr(buildPattern(lhs,lhsval,semval,cur));
      count += 1;
    }
  } while(advance_combo(cur,min,max));
  if (count == 0)
    throw SleighError("Greater than or equal constraint is impossible to match");
}

EquationAnd::EquationAnd(PatternEquation *l,PatternEquation *r)

{
  (left=l)->layClaim();
  (right=r)->layClaim();
}

EquationAnd::~EquationAnd(void)

{
  PatternEquation::release(left);
  PatternEquation::release(right);
}

void EquationAnd::genPattern(const vector<TokenPattern> &ops) const

{
  left->genPattern(ops);
  right->genPattern(ops);
  resultpattern = left->getTokenPattern().doAnd(right->getTokenPattern());
}

bool EquationAnd::resolveOperandLeft(OperandResolve &state) const

{
  int4 cur_rightmost = -1;	// Initially we don't know our rightmost
  int4 cur_size = -1;		//   or size traversed since rightmost
  bool res = right->resolveOperandLeft(state);
  if (!res) return false;
  if ((state.cur_rightmost != -1)&&(state.size != -1)) {
    cur_rightmost = state.cur_rightmost;
    cur_size = state.size;
  }
  res = left->resolveOperandLeft(state);
  if (!res) return false;
  if ((state.cur_rightmost == -1)||(state.size == -1)) {
    state.cur_rightmost = cur_rightmost;
    state.size = cur_size;
  }
  return true;
}

void EquationAnd::operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const

{
  left->operandOrder(ct,order);	// List operands left
  right->operandOrder(ct,order); //  to right
}

EquationOr::EquationOr(PatternEquation *l,PatternEquation *r)

{
  (left=l)->layClaim();
  (right=r)->layClaim();
}

EquationOr::~EquationOr(void)

{
  PatternEquation::release(left);
  PatternEquation::release(right);
}

void EquationOr::genPattern(const vector<TokenPattern> &ops) const

{
  left->genPattern(ops);
  right->genPattern(ops);
  resultpattern = left->getTokenPattern().doOr(right->getTokenPattern());
}

bool EquationOr::resolveOperandLeft(OperandResolve &state) const

{
  int4 cur_rightmost = -1;	// Initially we don't know our rightmost
  int4 cur_size = -1;		//   or size traversed since rightmost
  bool res = right->resolveOperandLeft(state);
  if (!res) return false;
  if ((state.cur_rightmost != -1)&&(state.size != -1)) {
    cur_rightmost = state.cur_rightmost;
    cur_size = state.size;
  }
  res = left->resolveOperandLeft(state);
  if (!res) return false;
  if ((state.cur_rightmost == -1)||(state.size == -1)) {
    state.cur_rightmost = cur_rightmost;
    state.size = cur_size;
  }
  return true;
}

void EquationOr::operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const

{
  left->operandOrder(ct,order);	// List operands left
  right->operandOrder(ct,order); //  to right
}

EquationCat::EquationCat(PatternEquation *l,PatternEquation *r)

{
  (left=l)->layClaim();
  (right=r)->layClaim();
}

EquationCat::~EquationCat(void)

{
  PatternEquation::release(left);
  PatternEquation::release(right);
}

void EquationCat::genPattern(const vector<TokenPattern> &ops) const

{
  left->genPattern(ops);
  right->genPattern(ops);
  resultpattern = left->getTokenPattern().doCat(right->getTokenPattern());
}

bool EquationCat::resolveOperandLeft(OperandResolve &state) const

{
  bool res = left->resolveOperandLeft(state);
  if (!res) return false;
  int4 cur_base = state.base;
  int4 cur_offset = state.offset;
  if ((!left->getTokenPattern().getLeftEllipsis())&&(!left->getTokenPattern().getRightEllipsis())) {
    // Keep the same base
    state.offset += left->getTokenPattern().getMinimumLength(); // But add to its size
  }
  else if (state.cur_rightmost != -1) {
    state.base = state.cur_rightmost;
    state.offset = state.size;
  }
  else if (state.size != -1) {
    state.offset += state.size;
  }
  else {
    state.base = -2;		// We have no anchor
  }
  int4 cur_rightmost = state.cur_rightmost;
  int4 cur_size = state.size;
  res = right->resolveOperandLeft(state);
  if (!res) return false;
  state.base = cur_base;	// Restore base and offset
  state.offset = cur_offset;
  if (state.cur_rightmost == -1) {
    if ((state.size != -1)&&(cur_rightmost != -1)&&(cur_size != -1)) {
      state.cur_rightmost = cur_rightmost;
      state.size += cur_size;
    }
  }
  return true;
}

void EquationCat::operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const

{
  left->operandOrder(ct,order);	// List operands left
  right->operandOrder(ct,order); //  to right
}

void EquationLeftEllipsis::genPattern(const vector<TokenPattern> &ops) const

{
  eq->genPattern(ops);
  resultpattern = eq->getTokenPattern();
  resultpattern.setLeftEllipsis(true);
}

bool EquationLeftEllipsis::resolveOperandLeft(OperandResolve &state) const

{
  int4 cur_base = state.base;
  state.base = -2;
  bool res = eq->resolveOperandLeft(state);
  if (!res) return false;
  state.base = cur_base;
  
  return true;
}

void EquationLeftEllipsis::operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const

{
  eq->operandOrder(ct,order);	// List operands
}

void EquationRightEllipsis::genPattern(const vector<TokenPattern> &ops) const

{
  eq->genPattern(ops);
  resultpattern = eq->getTokenPattern();
  resultpattern.setRightEllipsis(true);
}

bool EquationRightEllipsis::resolveOperandLeft(OperandResolve &state) const

{
  bool res = eq->resolveOperandLeft(state);
  if (!res) return false;
  state.size = -1;		// Cannot predict size
  return true;
}

void EquationRightEllipsis::operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const

{
  eq->operandOrder(ct,order);	// List operands
}

} // End namespace ghidra
