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
#include "architecture.hh"
#include "grammar.hh"
#include "test.hh"
#include <iostream>

namespace ghidra {

class FuncProtoTestEnvironment {
  Architecture *g;
  ProtoModel *mod1;
public:
  FuncProtoTestEnvironment(void);
  ~FuncProtoTestEnvironment(void);
  static void build(void);
  static void registerModel1(ostream &s);
  static void registerModel2(ostream &s);
  static void registerModel3(ostream &s);
};

static FuncProtoTestEnvironment theEnviron;

static Architecture *glb;

FuncProtoTestEnvironment::FuncProtoTestEnvironment(void)

{
  g = (Architecture *)0;
  mod1 = (ProtoModel *)0;
}

void FuncProtoTestEnvironment::build(void)

{
  if (theEnviron.g != (Architecture *)0) return;
  ArchitectureCapability *xmlCapability = ArchitectureCapability::getCapability("xml");
  istringstream s(
      "<binaryimage arch=\"Toy:LE:32:default:default\"></binaryimage>"
  );
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());

  ostringstream s2;
  s2 << "<specextensions> ";
  registerModel1(s2);
  registerModel2(s2);
  registerModel3(s2);
  s2 << "</specextensions>\n";
  istringstream s3(s2.str());
  doc = store.parseDocument(s3);
  store.registerTag(doc->getRoot());
  theEnviron.g = xmlCapability->buildArchitecture("", "", &cout);
  theEnviron.g->init(store);

  glb = theEnviron.g;
}

void FuncProtoTestEnvironment::registerModel1(ostream &s)

{
  const char *text =
      "<prototype name=\"__model1\" extrapop=\"unknown\" stackshift=\"4\">"
      "<input pointermax=\"4\">"
      "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r12\"/>"
        "</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r11\"/>"
        "</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r10\"/>"
        "</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r9\"/>"
        "</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r8\"/>"
        "</pentry>"
        "<pentry minsize=\"1\" maxsize=\"500\" align=\"4\">"
          "<addr offset=\"0\" space=\"stack\"/>"
        "</pentry>"
      "</input>"
      "<output>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r12\"/>"
        "</pentry>"
      "</output>"
    "</prototype>";
    s << text << endl;
}

void FuncProtoTestEnvironment::registerModel2(ostream &s)

{
  const char *text =
      "<prototype name=\"__model2\" extrapop=\"unknown\" stackshift=\"4\">"
      "<input>"
        "<pentry minsize=\"1\" maxsize=\"4\" metatype=\"ptr\"><register name=\"r1\"/>"
	"</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\" metatype=\"ptr\"><register name=\"r2\"/>"
	"</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\" metatype=\"float\" extension=\"float\"><register name=\"r3\"/>"
	"</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\" metatype=\"float\" extension=\"float\"><register name=\"r4\"/>"
	"</pentry>"
	"<pentry minsize=\"1\" maxsize=\"4\" metatype=\"float\" extension=\"float\"><register name=\"r5\"/>"
	"</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r10\"/>"
        "</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r9\"/>"
        "</pentry>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r8\"/>"
        "</pentry>"
        "<pentry minsize=\"5\" maxsize=\"8\">"
          "<addr space=\"join\" piece1=\"r10\" piece2=\"r9\"/>"
        "</pentry>"
        "<pentry minsize=\"1\" maxsize=\"500\" align=\"4\">"
          "<addr offset=\"0\" space=\"stack\"/>"
        "</pentry>"
      "</input>"
      "<output>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r12\"/>"
        "</pentry>"
      "</output>"
    "</prototype>";
    s << text << endl;
}

void FuncProtoTestEnvironment::registerModel3(ostream &s)

{
  const char *text =
      "<prototype name=\"__model3\" extrapop=\"unknown\" stackshift=\"4\">"
      "<input>"
        "<group>"
          "<pentry minsize=\"1\" maxsize=\"4\" metatype=\"float\" extension=\"float\"><register name=\"r3\"/>"
	  "</pentry>"
          "<pentry minsize=\"1\" maxsize=\"4\"> "
            "<register name=\"r10\"/> "
          "</pentry> "
        "</group> "
        "<group>"
          "<pentry minsize=\"1\" maxsize=\"4\" metatype=\"float\" extension=\"float\"><register name=\"r4\"/>"
	  "</pentry>"
          "<pentry minsize=\"1\" maxsize=\"4\"> "
            "<register name=\"r9\"/> "
          "</pentry> "
        "</group>"
        "<group>"
          "<pentry minsize=\"1\" maxsize=\"4\" metatype=\"float\" extension=\"float\"><register name=\"r5\"/>"
	    "</pentry>"
          "<pentry minsize=\"1\" maxsize=\"4\"> "
            "<register name=\"r8\"/> "
          "</pentry> "
        "</group> "
        "<pentry minsize=\"1\" maxsize=\"500\" align=\"4\"> "
          "<addr offset=\"0\" space=\"stack\"/> "
        "</pentry> "
      "</input>"
      "<output>"
        "<pentry minsize=\"1\" maxsize=\"4\">"
          "<register name=\"r12\"/>"
        "</pentry>"
      "</output>"
    "</prototype>";
    s << text << endl;
}

ProtoModel *getModel(const string &nm)

{
  FuncProtoTestEnvironment::build();
  return glb->protoModels[nm];
}

bool register_equal(ParameterPieces &piece,const string &nm)

{
  VarnodeData vData = glb->translate->getRegister(nm);
  if (vData.space != piece.addr.getSpace())
    return false;
  if (vData.offset != piece.addr.getOffset())
    return false;
  return true;
}

FuncProtoTestEnvironment::~FuncProtoTestEnvironment(void)

{
  if (g != (Architecture *)0)
    delete g;
}

TEST(funcproto_register) {
  ProtoModel *model = getModel("__model1");
  istringstream s("void func(int4 a,int4 b);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),3);
  ASSERT(res[0].addr.isInvalid());	// Placeholder for void return value
  ASSERT(register_equal(res[1],"r12"));
  ASSERT(register_equal(res[2],"r11"));
}

TEST(funcproto_smallregister) {
  ProtoModel *model = getModel("__model1");
  istringstream s("int4 func(char a,int4 b,int2 c,int4 d);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),5);
  ASSERT(register_equal(res[0],"r12"));	// output register
  ASSERT_EQUALS(res[0].type->getName(),"int4");
  ASSERT(register_equal(res[1],"r12"));
  ASSERT_EQUALS(res[1].type->getName(),"char");
  ASSERT(register_equal(res[2],"r11"));
  ASSERT_EQUALS(res[2].type->getName(),"int4");
  ASSERT(register_equal(res[3],"r10"));
  ASSERT_EQUALS(res[3].type->getName(),"int2");
  ASSERT(register_equal(res[4],"r9"));
  ASSERT_EQUALS(res[4].type->getName(),"int4");
}

TEST(funcproto_stackalign) {
  ProtoModel *model = getModel("__model1");
  istringstream s("int4 func(int4 a,int4 b,int4 c,int4 d,int4 e,int2 f,int1 *g);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),8);
  ASSERT(register_equal(res[0],"r12"));	// output register
  ASSERT_EQUALS(res[0].type->getName(),"int4");
  ASSERT(register_equal(res[1],"r12"));
  ASSERT_EQUALS(res[1].type,res[0].type);
  ASSERT(register_equal(res[2],"r11"));
  ASSERT_EQUALS(res[2].type,res[0].type);
  ASSERT(register_equal(res[3],"r10"));
  ASSERT_EQUALS(res[3].type,res[0].type);
  ASSERT(register_equal(res[4],"r9"));
  ASSERT_EQUALS(res[4].type,res[0].type);
  ASSERT(register_equal(res[5],"r8"));
  ASSERT_EQUALS(res[5].type,res[0].type);
  ASSERT_EQUALS(res[6].addr.getSpace(),glb->getStackSpace());
  ASSERT_EQUALS(res[6].addr.getOffset(),0x0);
  ASSERT_EQUALS(res[6].type->getName(),"int2");
  ASSERT_EQUALS(res[7].addr.getSpace(),glb->getStackSpace());
  ASSERT_EQUALS(res[7].addr.getOffset(),0x4);
  ASSERT_EQUALS(res[7].type->getMetatype(),TYPE_PTR);
}

TEST(funcproto_pointeroverflow) {
  ProtoModel *model = getModel("__model1");
  istringstream s("int2 func(int4 a,int8 b,int4 c);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),4);
  ASSERT(register_equal(res[0],"r12"));	// output register
  ASSERT_EQUALS(res[0].type->getName(),"int2");
  ASSERT(register_equal(res[1],"r12"));
  ASSERT_EQUALS(res[1].type->getName(),"int4");
  ASSERT(register_equal(res[2],"r11"));
  ASSERT_EQUALS(res[2].type->getMetatype(),TYPE_PTR);
  ASSERT_EQUALS(((TypePointer *)res[2].type)->getPtrTo()->getName(),"int8");
  ASSERT_EQUALS(res[2].flags,ParameterPieces::indirectstorage);
  ASSERT(register_equal(res[3],"r10"));
  ASSERT_EQUALS(res[3].type->getName(),"int4");
}

TEST(funcproto_stackoverflow) {
  ProtoModel *model = getModel("__model2");
  istringstream s("char func(int4 a,int8 b,int4 c);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),4);
  ASSERT(register_equal(res[0],"r12"));	// output register
  ASSERT_EQUALS(res[0].type->getName(),"char");
  ASSERT(register_equal(res[1],"r10"));
  ASSERT_EQUALS(res[1].type->getName(),"int4");
  ASSERT_EQUALS(res[2].addr.getSpace(),glb->getStackSpace());
  ASSERT_EQUALS(res[2].addr.getOffset(),0x0);		// Should overflow to stack
  ASSERT_EQUALS(res[2].type->getName(),"int8");
  ASSERT(register_equal(res[3],"r9"));			// Should resume with next register
  ASSERT_EQUALS(res[3].type->getName(),"int4");
}

TEST(funcproto_floatreg) {
  ProtoModel *model = getModel("__model2");
  istringstream s("void func(int4 a,float4 b,float4 c,int4 d,float4 d);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),6);
  ASSERT(res[0].addr.isInvalid());
  ASSERT(register_equal(res[1],"r10"));
  ASSERT(register_equal(res[2],"r3"));
  ASSERT_EQUALS(res[2].type->getName(),"float4");
  ASSERT(register_equal(res[3],"r4"));
  ASSERT_EQUALS(res[3].type->getName(),"float4");
  ASSERT(register_equal(res[4],"r9"));
  ASSERT(register_equal(res[5],"r5"));
  ASSERT_EQUALS(res[5].type->getName(),"float4");
}

TEST(funcproto_floattogeneric) {
  ProtoModel *model = getModel("__model2");
  istringstream s("float4 func(int4 a,float4 b,float4 c,float4 d,float4 e,float4 f);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),7);
  ASSERT(register_equal(res[0],"r12"));
  ASSERT_EQUALS(res[0].type->getName(),"float4");
  ASSERT(register_equal(res[1],"r10"));
  ASSERT(register_equal(res[2],"r3"));
  ASSERT_EQUALS(res[2].type->getName(),"float4");
  ASSERT(register_equal(res[3],"r4"));
  ASSERT_EQUALS(res[3].type->getName(),"float4");
  ASSERT(register_equal(res[4],"r5"));
  ASSERT_EQUALS(res[4].type->getName(),"float4");
  ASSERT(register_equal(res[5],"r9"));	// If float registers are exhausted, it should pick up with generic registers
  ASSERT_EQUALS(res[5].type->getName(),"float4");
  ASSERT(register_equal(res[6],"r8"));
  ASSERT_EQUALS(res[6].type->getName(),"float4");
}

TEST(funcproto_grouped) {
  ProtoModel *model = getModel("__model3");
  istringstream s("float4 func(int4 a,float4 b,float4 c,int4 d,float4 e);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),6);
  ASSERT(register_equal(res[0],"r12"));
  ASSERT_EQUALS(res[0].type->getName(),"float4");
  ASSERT(register_equal(res[1],"r10"));
  ASSERT_EQUALS(res[1].type->getName(),"int4");
  ASSERT(register_equal(res[2],"r4"));
  ASSERT_EQUALS(res[2].type->getName(),"float4");
  ASSERT(register_equal(res[3],"r5"));
  ASSERT_EQUALS(res[3].type->getName(),"float4");
  ASSERT_EQUALS(res[4].addr.getSpace(),glb->getStackSpace());
  ASSERT_EQUALS(res[4].addr.getOffset(),0x0);
  ASSERT_EQUALS(res[4].type->getName(),"int4");
  ASSERT_EQUALS(res[5].addr.getSpace(),glb->getStackSpace());
  ASSERT_EQUALS(res[5].addr.getOffset(),0x4);
  ASSERT_EQUALS(res[5].type->getName(),"float4");
}

TEST(funcproto_join) {
  ProtoModel *model = getModel("__model2");
  istringstream s("int2 func(int8 a,int4 b,int4 c);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),4);
  ASSERT(register_equal(res[0],"r12"));
  ASSERT_EQUALS(res[0].type->getName(),"int2");
  ASSERT_EQUALS(res[1].addr.getSpace(),glb->getJoinSpace());
  ASSERT_EQUALS(res[1].type->getName(),"int8");
  ASSERT(register_equal(res[2],"r8"));		// r10 and r9 are consumed, should pick up with r8
  ASSERT_EQUALS(res[2].type->getName(),"int4");
  ASSERT_EQUALS(res[3].addr.getSpace(),glb->getStackSpace());
  ASSERT_EQUALS(res[3].addr.getOffset(),0);
  ASSERT_EQUALS(res[3].type->getName(),"int4");
}

TEST(funcproto_nojoin) {
  ProtoModel *model = getModel("__model2");
  istringstream s("int4 func(int4 a,int8 b,int4 c);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),4);
  ASSERT(register_equal(res[0],"r12"));
  ASSERT_EQUALS(res[0].type->getName(),"int4");
  ASSERT(register_equal(res[1],"r10"));		// r10 consumed by first parameter
  ASSERT_EQUALS(res[1].type->getName(),"int4");
  ASSERT_EQUALS(res[2].addr.getSpace(),glb->getStackSpace());	// Big param must go to stack, can't use join
  ASSERT_EQUALS(res[2].addr.getOffset(),0);
  ASSERT_EQUALS(res[2].type->getName(),"int8");
  ASSERT(register_equal(res[3],"r9"));		// Next param can go back to register
  ASSERT_EQUALS(res[3].type->getName(),"int4");
}

TEST(funcproto_hiddenreturn) {
  ProtoModel *model = getModel("__model1");
  istringstream s("int8 func(int4 a,int4 b);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),4);
  ASSERT(register_equal(res[0],"r12"));		// Pointer to actual return value
  ASSERT_EQUALS(res[0].type->getMetatype(),TYPE_PTR);
  ASSERT_EQUALS(((TypePointer *)res[0].type)->getPtrTo()->getName(),"int8");
  ASSERT(register_equal(res[1],"r12"));		// Hidden return value pointer
  ASSERT_EQUALS(res[1].flags,ParameterPieces::hiddenretparm);
  ASSERT_EQUALS(res[1].type->getMetatype(),TYPE_PTR);
  ASSERT_EQUALS(((TypePointer *)res[1].type)->getPtrTo()->getName(),"int8");
  ASSERT(register_equal(res[2],"r11"));		// First formal parameter pushed to second slot
  ASSERT_EQUALS(res[2].type->getName(),"int4");
  ASSERT(register_equal(res[3],"r10"));
  ASSERT_EQUALS(res[3].type->getName(),"int4");
}

TEST(funcproto_mixedmeta) {
  ProtoModel *model = getModel("__model2");
  istringstream s("int4 func(char *a,int4 b,float4 c,int4 *d);");
  PrototypePieces pieces;
  parse_protopieces(pieces,s,glb);
  pieces.intypes.insert(pieces.intypes.begin(),pieces.outtype);
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces.intypes, res, false);
  ASSERT_EQUALS(res.size(),5);
  ASSERT(register_equal(res[0],"r12"));
  ASSERT(register_equal(res[1],"r1"));
  ASSERT_EQUALS(res[1].type->getMetatype(),TYPE_PTR);
  ASSERT(register_equal(res[2],"r10"));
  ASSERT(register_equal(res[3],"r3"));
  ASSERT(register_equal(res[4],"r2"));
  ASSERT_EQUALS(res[4].type->getMetatype(),TYPE_PTR);
}

void registerActive(ParamActive &paramActive,const string &nm,int4 sz)

{
  paramActive.registerTrial(glb->translate->getRegister(nm).getAddr(),sz);
  int4 num = paramActive.getNumTrials();
  paramActive.getTrial(num-1).markActive();
}

void stackActive(ParamActive &paramActive,uintb off,int4 sz)

{
  paramActive.registerTrial(Address(glb->getStackSpace(),off),sz);
  int4 num = paramActive.getNumTrials();
  paramActive.getTrial(num-1).markActive();
}

bool register_used(ParamTrial &trial,const string &nm)

{
  if (!trial.isUsed()) return false;
  VarnodeData vData = glb->translate->getRegister(nm);
  if (trial.getAddress() != vData.getAddr())
    return false;
  if (trial.getSize() != vData.size)
    return false;
  return true;
}

bool stack_used(ParamTrial &trial,uintb off,int4 sz)

{
  if (!trial.isUsed()) return false;
  Address addr(glb->getStackSpace(),off);
  if (trial.getAddress() != addr)
    return false;
  if (trial.getSize() != sz)
    return false;
  return true;
}

TEST(funcproto_recoverbasic)

{
  ProtoModel *model = getModel("__model1");
  ParamActive paramActive(false);
  registerActive(paramActive,"r11",4);
  registerActive(paramActive,"r10",4);
  registerActive(paramActive,"r12",4);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),3);
  ASSERT(register_used(paramActive.getTrial(0),"r12"));
  ASSERT(register_used(paramActive.getTrial(1),"r11"));
  ASSERT(register_used(paramActive.getTrial(2),"r10"));
}

TEST(funcproto_recoversmallreg)

{
  ProtoModel *model = getModel("__model1");
  ParamActive paramActive(false);
  registerActive(paramActive,"r11",4);
  registerActive(paramActive,"r12l",2);
  registerActive(paramActive,"r10l",2);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),3);
  ASSERT(register_used(paramActive.getTrial(0),"r12l"));
  ASSERT(register_used(paramActive.getTrial(1),"r11"));
  ASSERT(register_used(paramActive.getTrial(2),"r10l"));
}

TEST(funcproto_recoverstack)

{
  ProtoModel *model = getModel("__model2");
  ParamActive paramActive(false);
  registerActive(paramActive,"r10",4);
  stackActive(paramActive, 0, 2);
  registerActive(paramActive,"r8",4);
  stackActive(paramActive, 4, 4);
  registerActive(paramActive,"r9",4);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),10);
  ASSERT(paramActive.getTrial(0).isUnref());
  ASSERT(paramActive.getTrial(1).isUnref());
  ASSERT(paramActive.getTrial(2).isUnref());
  ASSERT(paramActive.getTrial(3).isUnref());
  ASSERT(paramActive.getTrial(4).isUnref());
  ASSERT(!paramActive.getTrial(0).isUsed());
  ASSERT(!paramActive.getTrial(1).isUsed());
  ASSERT(!paramActive.getTrial(2).isUsed());
  ASSERT(!paramActive.getTrial(3).isUsed());
  ASSERT(!paramActive.getTrial(4).isUsed());
  ASSERT(register_used(paramActive.getTrial(5),"r10"));
  ASSERT(register_used(paramActive.getTrial(6),"r9"));
  ASSERT(register_used(paramActive.getTrial(7),"r8"));
  ASSERT(stack_used(paramActive.getTrial(8),0,2));
  ASSERT(stack_used(paramActive.getTrial(9),4,4));
}

TEST(funcproto_recoverunrefregister)

{
  ProtoModel *model = getModel("__model1");
  ParamActive paramActive(false);
  registerActive(paramActive,"r12",4);
  registerActive(paramActive,"r10",4);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),3);
  ASSERT(register_used(paramActive.getTrial(0),"r12"));
  ASSERT(register_used(paramActive.getTrial(1),"r11"));
  ASSERT(paramActive.getTrial(1).isUnref());
  ASSERT(register_used(paramActive.getTrial(2),"r10"));
}

TEST(funcproto_recoverunrefstack)

{
  ProtoModel *model = getModel("__model2");
  ParamActive paramActive(false);
  stackActive(paramActive,4,4);
  stackActive(paramActive,12,4);
  registerActive(paramActive,"r8",4);
  registerActive(paramActive,"r9",4);
  registerActive(paramActive,"r10",4);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),12);
  ASSERT(paramActive.getTrial(0).isUnref());
  ASSERT(paramActive.getTrial(1).isUnref());
  ASSERT(paramActive.getTrial(2).isUnref());
  ASSERT(paramActive.getTrial(3).isUnref());
  ASSERT(paramActive.getTrial(4).isUnref());
  ASSERT(!paramActive.getTrial(0).isUsed());
  ASSERT(!paramActive.getTrial(1).isUsed());
  ASSERT(!paramActive.getTrial(2).isUsed());
  ASSERT(!paramActive.getTrial(3).isUsed());
  ASSERT(!paramActive.getTrial(4).isUsed());
  ASSERT(register_used(paramActive.getTrial(5),"r10"));
  ASSERT(register_used(paramActive.getTrial(6),"r9"));
  ASSERT(register_used(paramActive.getTrial(7),"r8"));
  ASSERT(stack_used(paramActive.getTrial(8),0,4));
  ASSERT(paramActive.getTrial(8).isUnref());
  ASSERT(stack_used(paramActive.getTrial(9),4,4));
  ASSERT(stack_used(paramActive.getTrial(10),8,4));
  ASSERT(paramActive.getTrial(10).isUnref());
  ASSERT(stack_used(paramActive.getTrial(11),12,4));
}

TEST(funcproto_recovergroups)

{
  ProtoModel *model = getModel("__model3");
  ParamActive paramActive(false);
  registerActive(paramActive,"r3",4);
  registerActive(paramActive,"r5",4);
  registerActive(paramActive,"r9",4);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),3);
  ASSERT(register_used(paramActive.getTrial(0),"r3"));
  ASSERT(register_used(paramActive.getTrial(1),"r9"));
  ASSERT(register_used(paramActive.getTrial(2),"r5"));
}

TEST(funcproto_recoverholes)

{
  ProtoModel *model = getModel("__model1");
  ParamActive paramActive(false);
  registerActive(paramActive,"r8",4);
  registerActive(paramActive,"r12",4);
  stackActive(paramActive,0,4);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),6);
  ASSERT(register_used(paramActive.getTrial(0),"r12"));
  ASSERT(!paramActive.getTrial(1).isUsed());
  ASSERT(paramActive.getTrial(1).isUnref());
  ASSERT(!paramActive.getTrial(2).isUsed());
  ASSERT(paramActive.getTrial(2).isUnref());
  ASSERT(!paramActive.getTrial(3).isUsed());
  ASSERT(paramActive.getTrial(3).isUnref());
  ASSERT(!paramActive.getTrial(4).isUsed());
  ASSERT(!paramActive.getTrial(5).isUsed());
}

TEST(funcproto_recoverfloat)

{
  ProtoModel *model = getModel("__model2");
  ParamActive paramActive(false);
  registerActive(paramActive,"r10",4);
  registerActive(paramActive,"r5",4);
  registerActive(paramActive,"r3",4);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),6);
  ASSERT(paramActive.getTrial(0).isUnref());
  ASSERT(paramActive.getTrial(1).isUnref());
  ASSERT(!paramActive.getTrial(0).isUsed());
  ASSERT(!paramActive.getTrial(1).isUsed());
  ASSERT(register_used(paramActive.getTrial(2),"r3"));
  ASSERT(register_used(paramActive.getTrial(3),"r4"));
  ASSERT(register_used(paramActive.getTrial(4),"r5"));
  ASSERT(register_used(paramActive.getTrial(5),"r10"));
}

TEST(funcproto_recovermixedmeta)

{
  ProtoModel *model = getModel("__model2");
  ParamActive paramActive(false);
  registerActive(paramActive,"r10",4);
  registerActive(paramActive,"r4",4);
  registerActive(paramActive,"r1",4);
  model->deriveInputMap(&paramActive);
  ASSERT_EQUALS(paramActive.getNumTrials(),6);
  ASSERT(register_used(paramActive.getTrial(0),"r1"));
  ASSERT(paramActive.getTrial(1).isUnref());
  ASSERT(!paramActive.getTrial(1).isUsed());
  ASSERT(register_used(paramActive.getTrial(2),"r3"));
  ASSERT(register_used(paramActive.getTrial(3),"r4"));
  ASSERT(paramActive.getTrial(4).isUnref());
  ASSERT(!paramActive.getTrial(4).isUsed());
  ASSERT(register_used(paramActive.getTrial(5),"r10"))
}

} // End namespace ghidra
