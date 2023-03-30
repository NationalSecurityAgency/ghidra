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

static Architecture *glb;
static TypeFactory *types;
static CastStrategy *strategy;
static Funcdata *dummyFunc;

class TypeTestEnvironment {
  Architecture *g;
public:
  TypeTestEnvironment(void);
  ~TypeTestEnvironment(void);
  static void build(void);
};

static TypeTestEnvironment theEnviron;

TypeTestEnvironment::TypeTestEnvironment(void)

{
  g = (Architecture *)0;
}

void TypeTestEnvironment::build(void)

{
  if (theEnviron.g != (Architecture *)0) return;
  ArchitectureCapability *xmlCapability = ArchitectureCapability::getCapability("xml");
  istringstream s(
      "<binaryimage arch=\"x86:LE:64:default:gcc\"></binaryimage>"
  );
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());

  theEnviron.g = xmlCapability->buildArchitecture("", "", &cout);
  theEnviron.g->init(store);

  glb = theEnviron.g;
  types = glb->types;
  strategy = glb->print->getCastStrategy();
  Address addr(glb->getDefaultCodeSpace(),0x1000);
  dummyFunc = glb->symboltab->getGlobalScope()->addFunction(addr, "dummy")->getFunction();
  dummyFunc->setHighLevel();
}

TypeTestEnvironment::~TypeTestEnvironment(void)

{
  if (g != (Architecture *)0)
    delete g;
}

Datatype *parse(const string &text) {
  istringstream s(text);
  string unused;
  return parse_type(s,unused,glb);
}

bool castPrinted(OpCode opc,Datatype *t1,Datatype *t2) {
  TypeOp *inst = glb->inst[opc];
  PcodeOp *op;
  Address addr(glb->getDefaultCodeSpace(),0x1000);
  if ((inst->getFlags() & PcodeOp::unary)!=0) {
    op = dummyFunc->newOp(1, addr);
    Varnode *vn1 = dummyFunc->newUnique(t2->getSize(), t2);
    Varnode *outvn = dummyFunc->newUniqueOut(t1->getSize(), op);
    outvn->updateType(t1, true, true);
    dummyFunc->opSetOpcode(op, opc);
    dummyFunc->opSetInput(op, vn1, 0);
  }
  else {
    op = dummyFunc->newOp(2, addr);
    Varnode *vn1 = dummyFunc->newUnique(t1->getSize(), t1);
    Varnode *vn2 = dummyFunc->newUnique(t2->getSize(), t2);
    dummyFunc->opSetOpcode(op, opc);
    dummyFunc->opSetInput(op, vn1, 0);
    dummyFunc->opSetInput(op, vn2, 1);
    dummyFunc->newUniqueOut(1, op);
  }
  return (inst->getInputCast(op, 0, strategy) != (Datatype *)0);
}

bool longPrinted(OpCode opc,Datatype *t1,uintb val)

{
  PcodeOp *op;
  Address addr(glb->getDefaultCodeSpace(),0x1000);
  op = dummyFunc->newOp(2, addr);
  Datatype *sa = glb->types->getBase(4,TYPE_INT);
  Varnode *vn1 = dummyFunc->newConstant(t1->getSize(), val);
  vn1->updateType(t1, false, true);
  Varnode *vn2 = dummyFunc->newUnique(sa->getSize(), sa);
  dummyFunc->opSetOpcode(op, opc);
  dummyFunc->opSetInput(op, vn1, 0);
  dummyFunc->opSetInput(op, vn2, 1);
  dummyFunc->newUniqueOut(vn1->getSize(), op);
  return glb->print->getCastStrategy()->markExplicitLongSize(op, 0);
}

TEST(cast_basic) {
  TypeTestEnvironment::build();
  ASSERT(castPrinted(CPUI_COPY,parse("int4"),parse("int2")));
  ASSERT(!castPrinted(CPUI_COPY,parse("int4"),parse("uint4")));
  ASSERT(castPrinted(CPUI_COPY,parse("int4 *"),parse("uint8")));
  ASSERT(!castPrinted(CPUI_COPY,parse("int1"),parse("bool")));
  ASSERT(!castPrinted(CPUI_COPY,parse("xunknown4"),parse("uint4")));
  ASSERT(!castPrinted(CPUI_COPY,parse("int4"),parse("xunknown4")));
  ASSERT(castPrinted(CPUI_COPY,parse("int4"),parse("float4")));
  ASSERT(castPrinted(CPUI_COPY,parse("int1 var[4]"),parse("uint4")));
  Datatype *typedefInt = types->getBase(4,TYPE_INT,"myint4");
  ASSERT(!castPrinted(CPUI_COPY,typedefInt,parse("int4")));
  ASSERT(!castPrinted(CPUI_COPY,parse("char"),parse("int1")));
  ASSERT(!castPrinted(CPUI_COPY,parse("uint1"),parse("char")));
}

TEST(cast_pointer) {
  TypeTestEnvironment::build();
  ASSERT(castPrinted(CPUI_COPY,parse("uint4 *"),parse("int4 *")));
  ASSERT(!castPrinted(CPUI_COPY,parse("void *"),parse("float4 *")));
  ASSERT(castPrinted(CPUI_COPY,parse("int2 *"),parse("void *")));
  Datatype *typedefInt = types->getBase(4,TYPE_INT,"myint4");
  Datatype *typedefPtr = types->getTypePointer(8,typedefInt,1);
  ASSERT(!castPrinted(CPUI_COPY,typedefPtr,parse("int4 *")));
  ASSERT(castPrinted(CPUI_COPY,parse("bool **"),parse("int1 **")));
  parse("struct structone { int4 a; int4 b; }");
  parse("struct structtwo { int4 a; int4 b; }");
  ASSERT(castPrinted(CPUI_COPY,parse("structone *"),parse("structtwo *")));
  ASSERT(!castPrinted(CPUI_COPY,parse("xunknown4 *"),parse("int4 *")));
  ASSERT(!castPrinted(CPUI_COPY,parse("uint4 *"),parse("xunknown4 *")));
  ASSERT(!castPrinted(CPUI_COPY,parse("char *"),parse("int1 *")));
  ASSERT(castPrinted(CPUI_COPY,parse("uint1 *"),parse("char *")));
  Datatype *ptrNamed = types->getTypePointer(8,parse("int4"),1,"myptrint4");
  ASSERT(!castPrinted(CPUI_COPY,parse("int4 *"),ptrNamed));
}

TEST(cast_enum) {
  TypeTestEnvironment::build();
  Datatype *enum1 = parse("enum enumone { ONE=1, TWO=2 }");
  ASSERT(!castPrinted(CPUI_COPY,parse("int8"),enum1));
  ASSERT(!castPrinted(CPUI_COPY,parse("uint8 *"),parse("enumone *")));
  ASSERT(!castPrinted(CPUI_COPY,enum1,parse("uint8")));
}

TEST(cast_compare) {
  TypeTestEnvironment::build();
  ASSERT(castPrinted(CPUI_INT_LESS,parse("int4"),parse("int4")));
  ASSERT(!castPrinted(CPUI_INT_LESS,parse("uint4"),parse("uint4")));
  ASSERT(!castPrinted(CPUI_INT_LESS,parse("int4 *"),parse("int4 *")));
  ASSERT(castPrinted(CPUI_INT_SLESS,parse("uint4"),parse("uint4")));
  ASSERT(!castPrinted(CPUI_INT_SLESS,parse("int4"),parse("int4")));
  ASSERT(castPrinted(CPUI_INT_EQUAL,parse("uint8"),parse("int4 *")));
  ASSERT(!castPrinted(CPUI_INT_EQUAL,parse("int4 *"),parse("uint8")));
  ASSERT(!castPrinted(CPUI_INT_NOTEQUAL,parse("int4"),parse("uint4")));
  ASSERT(!castPrinted(CPUI_INT_NOTEQUAL,parse("uint4"),parse("int4")));
  ASSERT(castPrinted(CPUI_INT_EQUAL,parse("int4"),parse("float4")));
}

TEST(type_ordering) {
  TypeTestEnvironment::build();
  ASSERT(parse("uint4")->compare(*parse("int4"),10) < 0);
  Datatype *intTypeDef = types->getBase(4,TYPE_INT,"myint4");
  ASSERT_NOT_EQUALS(parse("int4"),intTypeDef);
  ASSERT(parse("int4")->compareDependency(*intTypeDef) == 0);
  ASSERT(parse("int1")->compare(*parse("char"),10) < 0);
  ASSERT(parse("wchar2")->compare(*parse("int2"),10) < 0);
  ASSERT(parse("wchar4")->compare(*parse("int4"),10) < 0);
  ASSERT(parse("uint1")->compare(*parse("char"),10) < 0);
  Datatype *enum1 = parse("enum enum2 { ONE=1, TWO=2 }");
  ASSERT(enum1->compare(*parse("int8"),10) < 0);
  Datatype *struct1 = parse("struct struct1 { int4 a; int4 b; }");
  Datatype *struct2 = parse("struct struct2 { int4 a; int4 b; }");
  ASSERT_NOT_EQUALS(struct1,struct2);
  ASSERT(struct1->compareDependency(*struct2) == 0);
  ASSERT(parse("uint4")->compare(*parse("uint2"),10) < 0);
  ASSERT(parse("float8")->compare(*parse("float4"),10) < 0);
  ASSERT(parse("bool")->compare(*parse("uint1"),10) < 0);
  ASSERT(parse("uint4 *")->compare(*parse("int4 *"),10) < 0);
  ASSERT(parse("enum2 *")->compare(*parse("int8 *"),10) < 0);
  ASSERT(parse("int4 *")->compare(*parse("void *"),10) < 0);
  ASSERT(parse("int2 *")->compare(*parse("xunknown2 *"),10) < 0);
}

TEST(cast_integertoken) {
  TypeTestEnvironment::build();
  ASSERT(longPrinted(CPUI_INT_LEFT,parse("int8"),10));
  ASSERT(!longPrinted(CPUI_INT_LEFT,parse("int8"),0x100000000));
  ASSERT(longPrinted(CPUI_INT_SRIGHT,parse("int8"),-3));
  ASSERT(!longPrinted(CPUI_INT_SRIGHT,parse("int8"),0xffffffff7fffffff));
  ASSERT(longPrinted(CPUI_INT_SRIGHT,parse("int8"),0xffffffff80000000));
  ASSERT(longPrinted(CPUI_INT_RIGHT,parse("uint8"),0xffffffff));
  ASSERT(!longPrinted(CPUI_INT_RIGHT,parse("uint8"),0x100000000));
}

} // End namespace ghidra
