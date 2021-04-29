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
  virtual void saveXml(ostream &s) const {}	// We don't need this functionality for sleigh
};

class InjectPayloadSleigh : public InjectPayload {
  friend class PcodeInjectLibrarySleigh;
  ConstructTpl *tpl;
  string parsestring;
  string source;
public:
  InjectPayloadSleigh(const string &src,const string &nm,int4 tp);
  virtual ~InjectPayloadSleigh(void);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void restoreXml(const Element *el);
  virtual void printTemplate(ostream &s) const;
  virtual string getSource(void) const { return source; }

  static void checkParameterRestrictions(InjectContextSleigh &con,const vector<InjectParameter> &inputlist,
					 const vector<InjectParameter> &output,const string &source);
  static void setupParameters(InjectContextSleigh &con,ParserWalkerChange &walker,
			      const vector<InjectParameter> &inputlist,const vector<InjectParameter> &output,
			      const string &source);
};

class InjectPayloadCallfixup : public InjectPayloadSleigh {
  vector<string> targetSymbolNames;
public:
  InjectPayloadCallfixup(const string &sourceName);
  virtual void restoreXml(const Element *el);
};

class InjectPayloadCallother : public InjectPayloadSleigh {
public:
  InjectPayloadCallother(const string &sourceName);
  virtual void restoreXml(const Element *el);
};

class ExecutablePcodeSleigh : public ExecutablePcode {
  friend class PcodeInjectLibrarySleigh;
protected:
  string parsestring;
  ConstructTpl *tpl;
 public:
  ExecutablePcodeSleigh(Architecture *g,const string &src,const string &nm);
  virtual ~ExecutablePcodeSleigh(void);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void restoreXml(const Element *el);
  virtual void printTemplate(ostream &s) const;
};

class InjectPayloadDynamic : public InjectPayload {
  Architecture *glb;
  map<Address,Document *> addrMap;		// Map from address to specific inject
public:
  InjectPayloadDynamic(Architecture *g,const string &nm,int4 tp) : InjectPayload(nm,tp) { glb = g; dynamic = true; }
  virtual ~InjectPayloadDynamic(void);
  void restoreEntry(const Element *el);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void printTemplate(ostream &s) const { s << "dynamic"; }
  virtual string getSource(void) const { return "dynamic"; }
};

class PcodeInjectLibrarySleigh : public PcodeInjectLibrary {
  const SleighBase *slgh;
  vector<OpBehavior *> inst;
  InjectContextSleigh contextCache;
  int4 registerDynamicInject(InjectPayload *payload);
  InjectPayloadDynamic *forceDebugDynamic(int4 injectid);
  void parseInject(InjectPayload *payload);
protected:
  virtual int4 allocateInject(const string &sourceName,const string &name,int4 type);
  virtual void registerInject(int4 injectid);
public:
  PcodeInjectLibrarySleigh(Architecture *g,uintb tmpbase);
  virtual void restoreDebug(const Element *el);
  virtual int4 manualCallFixup(const string &name,const string &snippetstring);
  virtual int4 manualCallOtherFixup(const string &name,const string &outname,const vector<string> &inname,
				    const string &snippet);
  virtual InjectContext &getCachedContext(void) { return contextCache; }
  virtual const vector<OpBehavior *> &getBehaviors(void);
};

#endif
