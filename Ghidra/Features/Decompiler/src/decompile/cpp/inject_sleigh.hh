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
#ifndef __INJECT_SLEIGH__
#define __INJECT_SLEIGH__

#include "pcodeinject.hh"
#include "sleigh.hh"

class InjectContextSleigh : public InjectContext {
public:
  PcodeCacher cacher;
  ParserContext *pos;
  InjectContextSleigh(void) { pos = (ParserContext *)0; }
  virtual ~InjectContextSleigh(void);
  virtual void encode(Encoder &encoder) const {}	// We don't need this functionality for sleigh
};

class InjectPayloadSleigh : public InjectPayload {
  friend class PcodeInjectLibrarySleigh;
  ConstructTpl *tpl;
  std::string parsestring;
  std::string source;
protected:
  void decodeBody(Decoder &decoder);	///< Parse the <body> tag
public:
  InjectPayloadSleigh(const std::string &src,const std::string &nm,int4 tp);
  virtual ~InjectPayloadSleigh(void);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void decode(Decoder &decoder);
  virtual void printTemplate(std::ostream &s) const;
  virtual std::string getSource(void) const { return source; }

  static void checkParameterRestrictions(InjectContextSleigh &con,const std::vector<InjectParameter> &inputlist,
					 const std::vector<InjectParameter> &output,const std::string &source);
  static void setupParameters(InjectContextSleigh &con,ParserWalkerChange &walker,
			      const std::vector<InjectParameter> &inputlist,const std::vector<InjectParameter> &output,
			      const std::string &source);
};

class InjectPayloadCallfixup : public InjectPayloadSleigh {
  std::vector<std::string> targetSymbolNames;
public:
  InjectPayloadCallfixup(const std::string &sourceName);
  virtual void decode(Decoder &decoder);
};

class InjectPayloadCallother : public InjectPayloadSleigh {
public:
  InjectPayloadCallother(const std::string &sourceName);
  virtual void decode(Decoder &decoder);
};

class ExecutablePcodeSleigh : public ExecutablePcode {
  friend class PcodeInjectLibrarySleigh;
protected:
  std::string parsestring;
  ConstructTpl *tpl;
 public:
  ExecutablePcodeSleigh(Architecture *g,const std::string &src,const std::string &nm);
  virtual ~ExecutablePcodeSleigh(void);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void decode(Decoder &decoder);
  virtual void printTemplate(std::ostream &s) const;
};

class InjectPayloadDynamic : public InjectPayload {
  Architecture *glb;
  std::map<Address,Document *> addrMap;		// Map from address to specific inject
public:
  InjectPayloadDynamic(Architecture *g,const std::string &nm,int4 tp) : InjectPayload(nm,tp) { glb = g; dynamic = true; }
  virtual ~InjectPayloadDynamic(void);
  void decodeEntry(Decoder &decoder);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void decode(Decoder &decoder) { throw LowlevelError("decode not supported for InjectPayloadDynamic"); }
  virtual void printTemplate(std::ostream &s) const { s << "dynamic"; }
  virtual std::string getSource(void) const { return "dynamic"; }
};

class PcodeInjectLibrarySleigh : public PcodeInjectLibrary {
  const SleighBase *slgh;
  std::vector<OpBehavior *> inst;
  InjectContextSleigh contextCache;
  int4 registerDynamicInject(InjectPayload *payload);
  InjectPayloadDynamic *forceDebugDynamic(int4 injectid);
  void parseInject(InjectPayload *payload);
protected:
  virtual int4 allocateInject(const std::string &sourceName,const std::string &name,int4 type);
  virtual void registerInject(int4 injectid);
public:
  PcodeInjectLibrarySleigh(Architecture *g);
  virtual void decodeDebug(Decoder &decoder);
  virtual int4 manualCallFixup(const std::string &name,const std::string &snippetstring);
  virtual int4 manualCallOtherFixup(const std::string &name,const std::string &outname,const std::vector<std::string> &inname,
				    const std::string &snippet);
  virtual InjectContext &getCachedContext(void) { return contextCache; }
  virtual const std::vector<OpBehavior *> &getBehaviors(void);
};

#endif
