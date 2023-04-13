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
#include "translate.hh"
#include "test.hh"

namespace ghidra {

class TestAddrSpaceManager : public AddrSpaceManager {
public:
  TestAddrSpaceManager(Translate *t);
};

class DummyTranslate : public Translate {
public:
  virtual void initialize(DocumentStorage &store) {}
  virtual const VarnodeData &getRegister(const string &nm) const { throw LowlevelError("Cannot add register to DummyTranslate"); }
  virtual string getRegisterName(AddrSpace *base,uintb off,int4 size) const { return ""; }
  virtual void getAllRegisters(map<VarnodeData,string> &reglist) const {}
  virtual void getUserOpNames(vector<string> &res) const {}
  virtual int4 instructionLength(const Address &baseaddr) const { return -1; }
  virtual int4 oneInstruction(PcodeEmit &emit,const Address &baseaddr) const { return -1; }
  virtual int4 printAssembly(AssemblyEmit &emit,const Address &baseaddr) const { return -1; }
};

class MarshalTestEnvironment {
  DummyTranslate translate;
  TestAddrSpaceManager addrSpaceManage;
public:
  MarshalTestEnvironment(void);
  static void build(void);
};

static AddrSpaceManager *spcManager = (AddrSpaceManager *)0;
static MarshalTestEnvironment theEnviron;

TestAddrSpaceManager::TestAddrSpaceManager(Translate *t)
  : AddrSpaceManager()
{
  insertSpace(new AddrSpace(this,t,IPTR_PROCESSOR,"ram",8,1,3,AddrSpace::hasphysical,1));
}

MarshalTestEnvironment::MarshalTestEnvironment(void)
  : translate(), addrSpaceManage(&translate)
{

}

void MarshalTestEnvironment::build(void)

{
  spcManager = &theEnviron.addrSpaceManage;
}

void test_signed_attributes(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_ADDR);
  encoder.writeSignedInteger(ATTRIB_ALIGN, 3);	// 7-bits
  encoder.writeSignedInteger(ATTRIB_BIGENDIAN, -0x100);	// 14-bits
  encoder.writeSignedInteger(ATTRIB_CONSTRUCTOR, 0x1fffff);	// 21-bits
  encoder.writeSignedInteger(ATTRIB_DESTRUCTOR, -0xabcdefa);	// 28-bits
  encoder.writeSignedInteger(ATTRIB_EXTRAPOP, 0x300000000);	// 35-bits
  encoder.writeSignedInteger(ATTRIB_FORMAT, -0x30101010101);	// 42-bits
  encoder.writeSignedInteger(ATTRIB_ID, 0x123456789011);	// 49-bits
  encoder.writeSignedInteger(ATTRIB_INDEX, -0xf0f0f0f0f0f0f0);	// 56-bits
  encoder.writeSignedInteger(ATTRIB_METATYPE, 0x7fffffffffffffff);	// 63-bits
  encoder.closeElement(ELEM_ADDR);
  istringstream inStream(outStream.str());
  decoder.ingestStream(inStream);
  uint4 el = decoder.openElement(ELEM_ADDR);
  uint4 flags = 0;
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_ALIGN) {
      int8 val = decoder.readSignedInteger();
      flags |= 1;
      ASSERT_EQUALS(val, 3);
    }
    else if (attribId == ATTRIB_BIGENDIAN) {
      int8 val = decoder.readSignedInteger();
      flags |= 2;
      ASSERT_EQUALS(val, -0x100);
    }
    else if (attribId == ATTRIB_CONSTRUCTOR) {
      int8 val = decoder.readSignedInteger();
      flags |= 4;
      ASSERT_EQUALS(val, 0x1fffff);
    }
    else if (attribId == ATTRIB_DESTRUCTOR) {
      int8 val = decoder.readSignedInteger();
      flags |= 8;
      ASSERT_EQUALS(val, -0xabcdefa);
    }
    else if (attribId == ATTRIB_EXTRAPOP) {
      int8 val = decoder.readSignedInteger();
      flags |= 0x10;
      ASSERT_EQUALS(val, 0x300000000);
    }
    else if (attribId == ATTRIB_FORMAT) {
      int8 val = decoder.readSignedInteger();
      flags |= 0x20;
      ASSERT_EQUALS(val, -0x30101010101);
    }
    else if (attribId == ATTRIB_ID) {
      int8 val = decoder.readSignedInteger();
      flags |= 0x40;
      ASSERT_EQUALS(val, 0x123456789011);
    }
    else if (attribId == ATTRIB_INDEX) {
      int8 val = decoder.readSignedInteger();
      flags |= 0x80;
      ASSERT_EQUALS(val, -0xf0f0f0f0f0f0f0);
    }
    else if (attribId == ATTRIB_METATYPE) {
      int8 val = decoder.readSignedInteger();
      flags |= 0x100;
      ASSERT_EQUALS(val, 0x7fffffffffffffff);
    }
  }
  decoder.closeElement(el);
  ASSERT_EQUALS(flags,0x1ff);
}

void test_unsigned_attributes(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_ADDR);
  encoder.writeUnsignedInteger(ATTRIB_ALIGN, 3);	// 7-bits
  encoder.writeUnsignedInteger(ATTRIB_BIGENDIAN, 0x100);	// 14-bits
  encoder.writeUnsignedInteger(ATTRIB_CONSTRUCTOR, 0x1fffff);	// 21-bits
  encoder.writeUnsignedInteger(ATTRIB_DESTRUCTOR, 0xabcdefa);	// 28-bits
  encoder.writeUnsignedInteger(ATTRIB_EXTRAPOP, 0x300000000);	// 35-bits
  encoder.writeUnsignedInteger(ATTRIB_FORMAT, 0x30101010101);	// 42-bits
  encoder.writeUnsignedInteger(ATTRIB_ID, 0x123456789011);	// 49-bits
  encoder.writeUnsignedInteger(ATTRIB_INDEX, 0xf0f0f0f0f0f0f0);	// 56-bits
  encoder.writeUnsignedInteger(ATTRIB_METATYPE, 0x7fffffffffffffff);	// 63-bits
  encoder.writeUnsignedInteger(ATTRIB_MODEL, 0x8000000000000000);	// 64-bits
  encoder.closeElement(ELEM_ADDR);
  istringstream inStream(outStream.str());
  decoder.ingestStream(inStream);
  uint4 el = decoder.openElement(ELEM_ADDR);
  uint8 val = decoder.readUnsignedInteger(ATTRIB_ALIGN);
  ASSERT_EQUALS(val, 3);
  val = decoder.readUnsignedInteger(ATTRIB_BIGENDIAN);
  ASSERT_EQUALS(val, 0x100);
  val = decoder.readUnsignedInteger(ATTRIB_CONSTRUCTOR);
  ASSERT_EQUALS(val, 0x1fffff);
  val = decoder.readUnsignedInteger(ATTRIB_DESTRUCTOR);
  ASSERT_EQUALS(val, 0xabcdefa);
  val = decoder.readUnsignedInteger(ATTRIB_EXTRAPOP);
  ASSERT_EQUALS(val, 0x300000000);
  val = decoder.readUnsignedInteger(ATTRIB_FORMAT);
  ASSERT_EQUALS(val, 0x30101010101);
  val = decoder.readUnsignedInteger(ATTRIB_ID);
  ASSERT_EQUALS(val, 0x123456789011);
  val = decoder.readUnsignedInteger(ATTRIB_INDEX);
  ASSERT_EQUALS(val, 0xf0f0f0f0f0f0f0);
  val = decoder.readUnsignedInteger(ATTRIB_METATYPE);
  ASSERT_EQUALS(val, 0x7fffffffffffffff);
  val = decoder.readUnsignedInteger(ATTRIB_MODEL);
  ASSERT_EQUALS(val, 0x8000000000000000);
  decoder.closeElement(el);
}

TEST(marshal_signed_packed) {
  ostringstream outStream;

  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_signed_attributes(outStream, encoder, decoder);
}

TEST(marshal_signed_xml) {
  ostringstream outStream;

  theEnviron.build();
  XmlEncode encoder(outStream);
  XmlDecode decoder(spcManager);
  test_signed_attributes(outStream, encoder, decoder);
}

TEST(marshal_unsigned_packed) {
  ostringstream outStream;

  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_unsigned_attributes(outStream, encoder, decoder);
}

TEST(marshal_unsigned_xml) {
  ostringstream outStream;

  theEnviron.build();
  XmlEncode encoder(outStream);
  XmlDecode decoder(spcManager);
  test_unsigned_attributes(outStream, encoder, decoder);
}

void test_mixed_attributes(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_ADDR);
  encoder.writeSignedInteger(ATTRIB_ALIGN, 456);
  encoder.writeString(ATTRIB_EXTRAPOP, "unknown");
  encoder.closeElement(ELEM_ADDR);
  istringstream inStream(outStream.str());
  decoder.ingestStream(inStream);
  int4 alignVal = -1;
  int4 extrapopVal = -1;
  uint4 el = decoder.openElement(ELEM_ADDR);
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_ALIGN)
      alignVal = decoder.readSignedIntegerExpectString("00blah", 700);
    else if (attribId == ATTRIB_EXTRAPOP)
      extrapopVal = decoder.readSignedIntegerExpectString("unknown", 800);
  }
  decoder.closeElement(el);
  ASSERT_EQUALS(alignVal, 456);
  ASSERT_EQUALS(extrapopVal, 800);
}

TEST(marshal_mixed_packed) {
  ostringstream outStream;

  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_mixed_attributes(outStream, encoder, decoder);
}

TEST(marshal_mixed_xml) {
  ostringstream outStream;

  theEnviron.build();
  XmlEncode encoder(outStream);
  XmlDecode decoder(spcManager);
  test_mixed_attributes(outStream, encoder, decoder);
}


void test_attributes(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_DATA);
  encoder.writeBool(ATTRIB_ALIGN, true);
  encoder.writeBool(ATTRIB_BIGENDIAN, false);
  AddrSpace *spc = spcManager->getSpace(3);
  encoder.writeSpace(ATTRIB_SPACE, spc);
  encoder.writeString(ATTRIB_VAL,"");	// Empty string
  encoder.writeString(ATTRIB_VALUE,"hello");
  encoder.writeString(ATTRIB_CONSTRUCTOR,"<<\xe2\x82\xac>>&\"bl a  h\'\\bleh\n\t");
  string longString = "one to three four five six seven eight nine ten eleven twelve thirteen "
               "fourteen fifteen sixteen seventeen eighteen nineteen twenty twenty one "
      "blahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblah";
  encoder.writeString(ATTRIB_DESTRUCTOR,longString);
  encoder.closeElement(ELEM_DATA);
  istringstream inStream(outStream.str());
  decoder.ingestStream(inStream);
  uint4 el = decoder.openElement(ELEM_DATA);
  bool bval = decoder.readBool(ATTRIB_ALIGN);
  ASSERT(bval);
  bval = decoder.readBool(ATTRIB_BIGENDIAN);
  ASSERT(!bval);
  spc = decoder.readSpace(ATTRIB_SPACE);
  ASSERT_EQUALS(spc,spcManager->getSpace(3));
  string val = decoder.readString(ATTRIB_VAL);
  ASSERT_EQUALS(val,"");
  val = decoder.readString(ATTRIB_VALUE);
  ASSERT_EQUALS(val,"hello");
  val = decoder.readString(ATTRIB_CONSTRUCTOR);
  ASSERT_EQUALS(val,"<<\xe2\x82\xac>>&\"bl a  h\'\\bleh\n\t");
  val = decoder.readString(ATTRIB_DESTRUCTOR);
  ASSERT_EQUALS(val,longString);
  decoder.closeElement(el);
}

TEST(marshal_attribs_packed) {
  ostringstream outStream;
  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_attributes(outStream, encoder, decoder);
}

TEST(marshal_attribs_xml) {
  ostringstream outStream;
  theEnviron.build();
  XmlEncode encoder(outStream);
  XmlDecode decoder(spcManager);
  test_attributes(outStream, encoder, decoder);
}

void test_hierarchy(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_DATA);		// el1
  encoder.writeBool(ATTRIB_CONTENT, true);
  encoder.openElement(ELEM_INPUT);		// el2
  encoder.openElement(ELEM_OUTPUT);		// el3
  encoder.writeSignedInteger(ATTRIB_ID, 0x1000);
  encoder.openElement(ELEM_DATA);		// el4
  encoder.openElement(ELEM_DATA);		// el5
  encoder.openElement(ELEM_OFF);		// el6
  encoder.closeElement(ELEM_OFF);
  encoder.openElement(ELEM_OFF);		// el6
  encoder.writeString(ATTRIB_ID,"blahblah");
  encoder.closeElement(ELEM_OFF);
  encoder.openElement(ELEM_OFF);		// el6
  encoder.closeElement(ELEM_OFF);
  encoder.closeElement(ELEM_DATA);		// close el5
  encoder.closeElement(ELEM_DATA);		// close el4
  encoder.openElement(ELEM_SYMBOL);		// skip4
  encoder.writeUnsignedInteger(ATTRIB_ID, 17);
  encoder.openElement(ELEM_TARGET);		// skip5
  encoder.closeElement(ELEM_TARGET);		// close skip5
  encoder.closeElement(ELEM_SYMBOL);		// close skip4
  encoder.closeElement(ELEM_OUTPUT);		// close el3
  encoder.closeElement(ELEM_INPUT);		// close el2
  encoder.openElement(ELEM_INPUT);		// el2
  encoder.closeElement(ELEM_INPUT);
  encoder.openElement(ELEM_INPUT);		// el2
  encoder.closeElement(ELEM_INPUT);
  encoder.openElement(ELEM_INPUT);		// el2
  encoder.closeElement(ELEM_INPUT);
  encoder.openElement(ELEM_INPUT);		// el2
  encoder.closeElement(ELEM_INPUT);
  encoder.openElement(ELEM_INPUT);		// el2
  encoder.closeElement(ELEM_INPUT);
  encoder.openElement(ELEM_INPUT);		// el2
  encoder.closeElement(ELEM_INPUT);
  encoder.closeElement(ELEM_DATA);		// close el1
  istringstream inStream(outStream.str());
  decoder.ingestStream(inStream);
  uint4 el1 = decoder.openElement(ELEM_DATA);
  // Skip over the bool
  uint4 el2 = decoder.openElement(ELEM_INPUT);
  uint4 el3 = decoder.openElement(ELEM_OUTPUT);
  int4 val = decoder.readSignedInteger(ATTRIB_ID);
  ASSERT_EQUALS(val, 0x1000);
  uint4 el4 = decoder.peekElement();
  ASSERT_EQUALS(el4, ELEM_DATA.getId());
  decoder.openElement();
  uint4 el5 = decoder.openElement();
  ASSERT_EQUALS(el5, ELEM_DATA.getId());
  uint4 el6 = decoder.openElement(ELEM_OFF);
  decoder.closeElement(el6);
  el6 = decoder.openElement(ELEM_OFF);
  decoder.closeElement(el6);
  el6 = decoder.openElement(ELEM_OFF);
  decoder.closeElement(el6);
  decoder.closeElement(el5);
  decoder.closeElement(el4);
  decoder.closeElementSkipping(el3);
  decoder.closeElement(el2);
  el2 = decoder.openElement(ELEM_INPUT);
  decoder.closeElement(el2);
  el2 = decoder.openElement(ELEM_INPUT);
  decoder.closeElement(el2);
  decoder.closeElementSkipping(el1);
}

TEST(marshal_hierarchy_packed) {
  ostringstream outStream;
  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_hierarchy(outStream, encoder, decoder);
}

TEST(marshal_hierarchy_xml) {
  ostringstream outStream;
  theEnviron.build();
  XmlEncode encoder(outStream);
  XmlDecode decoder(spcManager);
  test_hierarchy(outStream, encoder, decoder);
}

void test_unexpected_eof(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_DATA);
  encoder.openElement(ELEM_INPUT);
  encoder.writeString(ATTRIB_NAME,"hello");
  encoder.closeElement(ELEM_INPUT);
  bool sawUnexpectedError = false;
  try {
    istringstream inStream(outStream.str());
    decoder.ingestStream(inStream);
    uint4 el1 = decoder.openElement(ELEM_DATA);
    uint4 el2 = decoder.openElement(ELEM_INPUT);
    decoder.closeElement(el2);
    decoder.closeElement(el1);
  } catch(DecoderError &err) {
    sawUnexpectedError = true;
  }
  ASSERT(sawUnexpectedError);
}

TEST(marshal_unexpected_packed) {
  ostringstream outStream;
  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_unexpected_eof(outStream, encoder, decoder);
}

TEST(marshal_unexpected_xml) {
  ostringstream outStream;
  theEnviron.build();
  XmlEncode encoder(outStream);
  XmlDecode decoder(spcManager);
  test_unexpected_eof(outStream, encoder, decoder);
}

void test_noremaining(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_INPUT);
  encoder.openElement(ELEM_OFF);
  encoder.closeElement(ELEM_OFF);
  encoder.closeElement(ELEM_INPUT);
  istringstream inStream(outStream.str());
  decoder.ingestStream(inStream);
  decoder.openElement(ELEM_INPUT);
  uint4 el2 = decoder.openElement(ELEM_OFF);
  decoder.closeElement(el2);
  bool sawNoRemaining = false;
  try {
    el2 = decoder.openElement(ELEM_OFF);
  } catch(DecoderError &err) {
    sawNoRemaining = true;
  }
  ASSERT(sawNoRemaining);
}

void test_openmismatch(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_INPUT);
  encoder.openElement(ELEM_OFF);
  encoder.closeElement(ELEM_OFF);
  encoder.closeElement(ELEM_INPUT);
  istringstream inStream(outStream.str());
  decoder.ingestStream(inStream);
  decoder.openElement(ELEM_INPUT);
  bool sawOpenMismatch = false;
  try {
    decoder.openElement(ELEM_OUTPUT);
  } catch(DecoderError &err) {
    sawOpenMismatch = true;
  }
  ASSERT(sawOpenMismatch);
}

void test_closemismatch(ostringstream &outStream,Encoder &encoder,Decoder &decoder)

{
  encoder.openElement(ELEM_INPUT);
  encoder.openElement(ELEM_OFF);
  encoder.closeElement(ELEM_OFF);
  encoder.closeElement(ELEM_INPUT);
  istringstream inStream(outStream.str());
  decoder.ingestStream(inStream);
  uint4 el1 = decoder.openElement(ELEM_INPUT);
  bool sawCloseMismatch = false;
  try {
    decoder.closeElement(el1);
  } catch(DecoderError &err) {
    sawCloseMismatch = true;
  }
  ASSERT(sawCloseMismatch);
}

TEST(marshal_noremaining_packed) {
  ostringstream outStream;
  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_noremaining(outStream, encoder, decoder);
}

TEST(marshal_noremaining_xml) {
  ostringstream outStream;
  theEnviron.build();
  XmlEncode encoder(outStream);
  XmlDecode decoder(spcManager);
  test_noremaining(outStream, encoder, decoder);
}

TEST(marshal_openmismatch_packed) {
  ostringstream outStream;
  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_openmismatch(outStream, encoder, decoder);
}

TEST(marshal_openmismatch_xml) {
  ostringstream outStream;
  theEnviron.build();
  XmlEncode encoder(outStream);
  XmlDecode decoder(spcManager);
  test_openmismatch(outStream, encoder, decoder);
}

TEST(marshal_closemismatch_packed) {
  ostringstream outStream;
  theEnviron.build();
  PackedEncode encoder(outStream);
  PackedDecode decoder(spcManager);
  test_closemismatch(outStream, encoder, decoder);
}

TEST(marshal_bufferpad) {
  ASSERT_EQUALS(PackedDecode::BUFFER_SIZE,1024);
  ostringstream s;
  PackedEncode encoder(s);
  encoder.openElement(ELEM_INPUT);		// 1-byte
  for(int4 i=0;i<511;++i)			// 1022-bytes
    encoder.writeBool(ATTRIB_CONTENT, (i&1) == 0);
  encoder.closeElement(ELEM_INPUT);
  ASSERT_EQUALS(s.str().length(),1024);		// Encoding should exactly fill one buffer
  istringstream s2(s.str());
  PackedDecode decoder(spcManager);
  decoder.ingestStream(s2);
  uint4 el = decoder.openElement(ELEM_INPUT);
  for(int4 i=0;i<511;++i) {
    uint4 attribId = decoder.getNextAttributeId();
    ASSERT_EQUALS(attribId,ATTRIB_CONTENT.getId());
    bool val = decoder.readBool();
    ASSERT_EQUALS(val, (i&1) == 0);
  }
  uint4 nextel = decoder.peekElement();
  ASSERT_EQUALS(nextel,0);
  decoder.closeElement(el);
}

} // End namespace ghidra
