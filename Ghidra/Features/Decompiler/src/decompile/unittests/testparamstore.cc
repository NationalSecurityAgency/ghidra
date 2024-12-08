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

namespace ghidra {

class ParamStoreEnvironment {
  map<string,Architecture *> loadedArches;
  Architecture *buildArch(const string &arch);
public:
  ~ParamStoreEnvironment(void);
  ProtoModel *getModel(const string &arch,const string &model);
  void parseType(ProtoModel *model,const string &definition);
  bool test(ProtoModel *model,const string &signature,const string &stores);
  static void parseJoin(ProtoModel *model,const string &join,VarnodeData &res);
  static void parseStore(ProtoModel *model,const string &name,VarnodeData &res);
  static void parseStores(ProtoModel *model,vector<VarnodeData> &res,const string &names);
  static bool comparePiece(const VarnodeData &vData,ParameterPieces &piece);
};

static ParamStoreEnvironment theEnviron;

Architecture *ParamStoreEnvironment::buildArch(const string &arch)

{
  map<string,Architecture *>::const_iterator iter = loadedArches.find(arch);
  if (iter != loadedArches.end()) {
    return (*iter).second;
  }
  ArchitectureCapability *xmlCapability = ArchitectureCapability::getCapability("xml");
  istringstream s(
      "<binaryimage arch=\"" + arch + "\"></binaryimage>"
  );
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());

  Architecture *g = xmlCapability->buildArchitecture("", "", &cout);
  g->init(store);
  loadedArches[arch] = g;
  return g;
}

ParamStoreEnvironment::~ParamStoreEnvironment(void)

{
  for(map<string,Architecture *>::const_iterator iter=loadedArches.begin();iter!=loadedArches.end();++iter) {
    delete (*iter).second;
  }
}

ProtoModel *ParamStoreEnvironment::getModel(const string &arch,const string &model)

{
  Architecture *glb = buildArch(arch);
  return glb->protoModels[model];
}

void ParamStoreEnvironment::parseType(ProtoModel *model,const string &definition)

{
  istringstream s(definition);
  parse_C(model->getArch(),s);
}

bool ParamStoreEnvironment::test(ProtoModel *model,const string &signature,const string &stores)

{
  istringstream s(signature);
  PrototypePieces pieces;
  parse_protopieces(pieces,s,model->getArch());
  vector<ParameterPieces> res;
  model->assignParameterStorage(pieces, res, false);
  vector<VarnodeData> storeData;
  parseStores(model,storeData,stores);
  if (storeData.size() != res.size())
    return false;
  for(int4 i=0;i<res.size();++i) {
    if (!comparePiece(storeData[i],res[i]))
      return false;
  }
  return true;
}

void ParamStoreEnvironment::parseJoin(ProtoModel *model,const string &join,VarnodeData &res)

{
  vector<VarnodeData> pieces;
  size_t pos = join.find(' ',0) + 1;
  for(;;) {
    size_t nextpos = join.find(' ',pos);
    string el;
    if (nextpos == string::npos)
      el = join.substr(pos);
    else
      el = join.substr(pos,nextpos - pos);
    pieces.push_back(VarnodeData());
    parseStore(model,el,pieces.back());
    if (nextpos == string::npos)
      break;
    pos = nextpos + 1;
  }
  int4 size = (pieces.size() == 1) ? 4 : 0;	// Assume a single piece join is a 4-byte float in a bigger register
  JoinRecord *joinRec = model->getArch()->findAddJoin(pieces, size);
  res = joinRec->getUnified();
}

void ParamStoreEnvironment::parseStore(ProtoModel *model,const string &name,VarnodeData &res)

{
  if (name == "void") {
    res.space = (AddrSpace *)0;
    res.offset = 0;
    res.size = 0;
    return;
  }
  if (name.compare(0,5,"stack",5) == 0) {
    size_t pos = name.find(':');
    istringstream s(name.substr(5,pos));
    res.space = model->getArch()->getStackSpace();
    s >> hex >> res.offset;
    res.size = 1;
    if (pos != string::npos) {
      istringstream t(name.substr(pos+1));
      t >> dec >> res.size;
    }
    return;
  }
  else if (name.compare(0,4,"join",4) == 0) {
    parseJoin(model,name,res);
    return;
  }
  string regname;
  size_t pos = name.find(':');
  int4 sz = 0;
  if (pos != string::npos) {
    istringstream s(name.substr(pos + 1));
    s >> dec >> sz;
    regname = name.substr(0,pos);
  }
  else
    regname = name;
  res = model->getArch()->translate->getRegister(regname);
  if (sz != 0) {
    if (res.space->isBigEndian())
      res.offset += (res.size - sz);
    res.size = sz;
  }
}

void ParamStoreEnvironment::parseStores(ProtoModel *model,vector<VarnodeData> &res,const string &names)

{
  size_t pos = 0;
  for(;;) {
    size_t nextpos = names.find(',',pos);
    string el;
    if (nextpos == string::npos)
      el = names.substr(pos);
    else
      el = names.substr(pos,nextpos - pos);
    res.push_back(VarnodeData());
    parseStore(model,el,res.back());
    if (nextpos == string::npos)
      break;
    pos = nextpos + 1;
  }
}

bool ParamStoreEnvironment::comparePiece(const VarnodeData &vData,ParameterPieces &piece)

{
  if (vData.space == (AddrSpace *)0) {
    return (piece.type->getMetatype() == TYPE_VOID);
  }
  if (vData.space != piece.addr.getSpace())
    return false;
  if (vData.offset != piece.addr.getOffset())
    return false;
  if (vData.size != piece.type->getSize())
    return false;
  return true;
}

TEST(paramstore_x64) {
  ProtoModel *model = theEnviron.getModel("x86:LE:64:default:gcc","__stdcall");
  ASSERT(theEnviron.test(model,"void func(int4,int4);","void,EDI,ESI"));
  ASSERT(theEnviron.test(model,"void func(float4,float4);","void,XMM0:4,XMM1:4"));
  ASSERT(theEnviron.test(model, "void func(int2 a,int4 b,int1 c);", "void,DI,ESI,DX:1"));
  ASSERT(theEnviron.test(model, "void func(int8,int8);", "void,RDI,RSI"));
  ASSERT(theEnviron.test(model, "void func(float8,float8);", "void,XMM0:8,XMM1:8"));
  ASSERT(theEnviron.test(model, "void func(int4,float4,int4,float4);", "void,EDI,XMM0:4,ESI,XMM1:4"));
  ASSERT(theEnviron.test(model, "void func(float4,int4,float4,int4);", "void,XMM0:4,EDI,XMM1:4,ESI"));
  ASSERT(theEnviron.test(model, "void func(int4,float8,float8,int4);", "void,EDI,XMM0:8,XMM1:8,ESI"));
  ASSERT(theEnviron.test(model, "void func(float8,int8,int8,float8);", "void,XMM0:8,RDI,RSI,XMM1:8"));
  ASSERT(theEnviron.test(model, "void func(float10);", "void,stack8:10"));
  ASSERT(theEnviron.test(model, "void func(float4,float10,float4);", "void,XMM0:4,stack8:10,XMM1:4"));
  theEnviron.parseType(model,"struct intfloatpair { int4 a; float4 b;};");
  ASSERT(theEnviron.test(model, "void func(intfloatpair);", "void,RDI"));
  theEnviron.parseType(model,"struct longfloatpair { int8 a; float4 b;};");
  ASSERT(theEnviron.test(model, "void func(int4,longfloatpair);", "void,EDI,join XMM0:8 RSI"));
  theEnviron.parseType(model,"struct longdoublepair { int8 a; float8 b;};");
  ASSERT(theEnviron.test(model, "void func(int4,longdoublepair);", "void,EDI,join XMM0:8 RSI"));
  theEnviron.parseType(model,"struct intdoublepair { int4 a; float8 b;};");
  ASSERT(theEnviron.test(model, "void func(int4,intdoublepair);", "void,EDI,join XMM0:8 RSI"));
  theEnviron.parseType(model,"struct floatintpair { float4 a; int4 b;};");
  ASSERT(theEnviron.test(model, "void func(int4,floatintpair);", "void,EDI,RSI"));
  theEnviron.parseType(model,"struct doubleintpair { float8 a; int4 b;};");
  ASSERT(theEnviron.test(model, "void func(int4,doubleintpair);", "void,EDI,join RSI XMM0:8"));
  theEnviron.parseType(model,"struct intintfloat { int4 a; int4 b; float4 c; };");
  ASSERT(theEnviron.test(model, "void func(int4,intintfloat);", "void,EDI,join XMM0:4 RSI"));
  theEnviron.parseType(model,"struct intintfloatfloat { int4 a; int4 b; float4 c; float4 d;};");
  ASSERT(theEnviron.test(model, "void func(int4,intintfloatfloat);", "void,EDI,join XMM0:8 RSI"));
  theEnviron.parseType(model,"struct intfloatfloatint { int4 a; float4 b; float4 c; int4 d;};");
  ASSERT(theEnviron.test(model, "void func(int4,intfloatfloatint);", "void,EDI,join RDX RSI"));
  theEnviron.parseType(model,"struct intfloatfloat { int4 a; float4 b; float4 c; };");
  ASSERT(theEnviron.test(model, "void func(int4,intfloatfloat);", "void,EDI,join XMM0:4 RSI"));
  theEnviron.parseType(model,"struct floatfloatpair { float4 a; float4 b; };");
  ASSERT(theEnviron.test(model, "void func(int4,floatfloatpair);", "void,EDI,XMM0:8"));
  theEnviron.parseType(model,"struct doublefloatpair { float8 a; float4 b; };");
  ASSERT(theEnviron.test(model, "void func(int4,doublefloatpair);", "void,EDI,join XMM1:8 XMM0:8"));
  theEnviron.parseType(model,"struct floatfloatfloat { float4 a; float4 b; float4 c; };");
  ASSERT(theEnviron.test(model, "void func(floatfloatfloat,int8);", "void,join XMM1:4 XMM0:8,RDI"));
  theEnviron.parseType(model,"struct intintintint { int4 a; int4 b; int4 c; int4 d; };");
  ASSERT(theEnviron.test(model, "void func(intintintint);", "void,join RSI RDI"));
  ASSERT(theEnviron.test(model, "void func(int4,intintintint);", "void,EDI,join RDX RSI"));
  theEnviron.parseType(model,"struct intintintintint { int4 a; int4 b; int4 c; int4 d; int4 e;};");
  ASSERT(theEnviron.test(model, "void func(intintintintint);", "void,stack8:20"));
  ASSERT(theEnviron.test(model, "void func(float4,float4,float4,float4,float4,float4,float4,float4,longfloatpair);",
			 "void,XMM0:4,XMM1:4,XMM2:4,XMM3:4,XMM4:4,XMM5:4,XMM6:4,XMM7:4,stack8:16"));
  ASSERT(theEnviron.test(model, "void func(xunknown4,xunknown8);", "void,EDI,RSI"));
  ASSERT(theEnviron.test(model, "intintintint func(void);", "join RDX RAX"));
  ASSERT(theEnviron.test(model, "floatintpair func(void);", "RAX"));
  ASSERT(theEnviron.test(model, "longfloatpair func(void);", "join XMM0:8 RAX"));
  ASSERT(theEnviron.test(model, "longdoublepair func(void);", "join XMM0:8 RAX"));
  ASSERT(theEnviron.test(model, "doubleintpair func(void);", "join RAX XMM0:8"));
  ASSERT(theEnviron.test(model, "floatfloatfloat func(void);", "join XMM1:4 XMM0:8"));
  theEnviron.parseType(model, "struct doubledoublepair { float8 a; float8 b; };");
  ASSERT(theEnviron.test(model, "doubledoublepair func(void);", "join XMM1:8 XMM0:8"));
  ASSERT(theEnviron.test(model, "floatfloatpair func(void);", "XMM0:8"));
  ASSERT(theEnviron.test(model, "intintintintint func(void);", "RAX,RDI"));
  theEnviron.parseType(model, "struct doubleintintint { float8 a; int4 b; int4 c; int4 d; };");
  ASSERT(theEnviron.test(model, "doubleintintint func(void);", "RAX,RDI"));
}

TEST(paramstore_aarch64_cdecl) {
  ProtoModel *model = theEnviron.getModel("AARCH64:LE:64:v8A:default","__cdecl");
  ASSERT(theEnviron.test(model, "void func(int2 a,int4 b,int1 c);", "void,w0:2,w1,w2:1"));
  ASSERT(theEnviron.test(model, "void func(int4, int4);", "void,w0,w1"));
  ASSERT(theEnviron.test(model, "void func(int8,int8);", "void,x0,x1"));
  ASSERT(theEnviron.test(model, "void func(float4,float4);", "void,s0,s1"));
  ASSERT(theEnviron.test(model, "void func(float8,float8);", "void,d0,d1"));
  ASSERT(theEnviron.test(model, "void func(int4,float4,int4,float4);", "void,w0,s0,w1,s1"));
  ASSERT(theEnviron.test(model, "void func(float4,int4,float4,int4);", "void,s0,w0,s1,w1"));
  ASSERT(theEnviron.test(model, "void func(int4,float8,float8,int4);", "void,w0,d0,d1,w1"));
  ASSERT(theEnviron.test(model, "void func(float8,int8,int8,float8);", "void,d0,x0,x1,d1"));
  ASSERT(theEnviron.test(model, "void func(float16);", "void,q0"));
  ASSERT(theEnviron.test(model, "void func(float4,float16);", "void,s0,q1"));
  ASSERT(theEnviron.test(model, "void func(int4,int4,int4,int4,int4,int4,int4,int4,int4,int4);",
		"void,w0,w1,w2,w3,w4,w5,w6,w7,stack0:4,stack8:4"));
  ASSERT(theEnviron.test(model, "void func(float4,float4,float4,float4,float4,float4,float4,float4,float4,float4);",
		"void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,stack8:4"));
  ASSERT(theEnviron.test(model, "void func(float4,float4,float4,float4,float4,float4,float4,float4,float16);",
		"void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:16"));
  ASSERT(theEnviron.test(model, "void func(float4,float4,float4,float4,float4,float4,float4,float4,float4,float16);",
		"void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,stack10:16"));
  ASSERT(theEnviron.test(model, "void func(int4,int4,int4,int4,int4,int4,int4,int4,int4,float4);",
		"void,w0,w1,w2,w3,w4,w5,w6,w7,stack0:4,s0"));
  ASSERT(theEnviron.test(model, "void func(float4,float4,float4,float4,float4,float4,float4,float4,float4,int4);",
		"void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,w0"));

  theEnviron.parseType(model,"struct intpair { int4 a; int4 b;};");
  ASSERT(theEnviron.test(model, "void func(intpair);", "void,x0"));

  theEnviron.parseType(model,"struct longpair { int8 a; int8 b; };");
  ASSERT(theEnviron.test(model, "void func(longpair);", "void,join x1 x0"));

  theEnviron.parseType(model,"struct longquad { int8 a; int8 b; int8 c; int8 d; };");
  ASSERT(theEnviron.test(model, "void func(longquad);", "void,x0"));

  theEnviron.parseType(model,"struct floatdouble { float4 a; float8 b; };");
  ASSERT(theEnviron.test(model, "void func(floatdouble);", "void,join x1 x0"));

  theEnviron.parseType(model,"struct intfloat { int4 a; float4 b; };");
  ASSERT(theEnviron.test(model, "void func(intfloat);", "void,x0"));

  theEnviron.parseType(model,"struct longdoublestruct { int8 a; float8 b; };");
  ASSERT(theEnviron.test(model, "void func(longdoublestruct);", "void,join x1 x0"));

  ASSERT(theEnviron.test(model, "int4 func(void);", "w0"));
  ASSERT(theEnviron.test(model, "float4 func(void);", "s0"));
  ASSERT(theEnviron.test(model, "float8 func(void);", "d0"));

  ASSERT(theEnviron.test(model, "intpair func(void);", "x0"));
  ASSERT(theEnviron.test(model, "longpair func(void);", "join x1 x0"));
  ASSERT(theEnviron.test(model, "longquad func(void);", "void,x8"));

  theEnviron.parseType(model,"struct floatpair { float4 a; float4 b; };");
  ASSERT(theEnviron.test(model, "void func(floatpair);", "void,join s1 s0"));

  theEnviron.parseType(model,"struct floatpairpair { floatpair a; floatpair b; };");
  ASSERT(theEnviron.test(model, "void func(floatpairpair);", "void,join s3 s2 s1 s0"));

  theEnviron.parseType(model,"struct doublequad { float8 a; float8 b; float8 c; float8 d; };");
  ASSERT(theEnviron.test(model, "void func(doublequad);", "void,join d3 d2 d1 d0"));
}

}
