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
/// \file inject_sleigh.hh
/// \brief Implementation of p-code injection using the internal SLEIGH engine to build the p-code ops

#ifndef __INJECT_SLEIGH_HH__
#define __INJECT_SLEIGH_HH__

#include "pcodeinject.hh"
#include "sleigh.hh"

namespace ghidra {

/// \brief Context for performing injection using the SLEIGH engine
class InjectContextSleigh : public InjectContext {
public:
  PcodeCacher cacher;		///< Cache of p-code data accumulated just prior to injection
  ParserContext *pos;		///< Context for final parsing and emitting of p-code during injection
  InjectContextSleigh(void) { pos = (ParserContext *)0; }	///< Constructor
  virtual ~InjectContextSleigh(void);
  virtual void encode(Encoder &encoder) const {}	///< We don't need this functionality for sleigh
};

/// \brief An injection payload built by the SLEIGH engine
///
/// The p-code ops for the injection are described using SLEIGH syntax.
/// This object can hold both the SLEIGH syntax as a string or the p-code templates
/// (VarnodeTpl and OpTpl) that are prepared for emitting the p-code for the injection.
class InjectPayloadSleigh : public InjectPayload {
  friend class PcodeInjectLibrarySleigh;
  ConstructTpl *tpl;			///< The VarnodeTpl and OpTpl objects prepared for injection
  string parsestring;			///< SLEIGH syntax describing the injection p-code
  string source;			///< A description of the document containing the SLEIGH syntax
protected:
  void decodeBody(Decoder &decoder);	///< Parse the \<body> tag
public:
  InjectPayloadSleigh(const string &src,const string &nm,int4 tp);	///< Constructor for use with decode
  virtual ~InjectPayloadSleigh(void);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void decode(Decoder &decoder);
  virtual void printTemplate(ostream &s) const;
  virtual string getSource(void) const { return source; }

  static void checkParameterRestrictions(InjectContextSleigh &con,const vector<InjectParameter> &inputlist,
					 const vector<InjectParameter> &output,const string &source);
  static void setupParameters(InjectContextSleigh &con,ParserWalkerChange &walker,
			      const vector<InjectParameter> &inputlist,const vector<InjectParameter> &output,
			      const string &source);
};

/// \brief An injection payload, described by SLEIGH, for replacing CALL ops to specific functions
class InjectPayloadCallfixup : public InjectPayloadSleigh {
  vector<string> targetSymbolNames;	///< Names (symbols) of specific functions to replace with \b this payload
public:
  InjectPayloadCallfixup(const string &sourceName);	///< Constructor
  virtual void decode(Decoder &decoder);
};

/// \brief An injection payload, described by SLEIGH, for replacing specific user (CALLOTHER) ops
class InjectPayloadCallother : public InjectPayloadSleigh {
public:
  InjectPayloadCallother(const string &sourceName);	///< Constructor
  virtual void decode(Decoder &decoder);
};

/// \brief A p-code snippet, described by SLEIGH, that can be executed as a script
class ExecutablePcodeSleigh : public ExecutablePcode {
  friend class PcodeInjectLibrarySleigh;
protected:
  string parsestring;		///< SLEIGH syntax describing the p-code snippet
  ConstructTpl *tpl;		///< Parsed template objects (VarnodeTpl and OpTpl) ready for injection
 public:
  ExecutablePcodeSleigh(Architecture *g,const string &src,const string &nm);
  virtual ~ExecutablePcodeSleigh(void);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void decode(Decoder &decoder);
  virtual void printTemplate(ostream &s) const;
};

/// \brief A debugging placeholder for a payload that changes depending on context
///
/// Implemented as a simple map from an Address to an XML description of the p-code sequence to inject.
/// This is used internally by PcodeInjectLibrarySleigh in a debug environment to hold multiple payloads
/// for objects where InjectPayload::isDynamic() returns \b true.
class InjectPayloadDynamic : public InjectPayload {
  Architecture *glb;				///< The architecture owning \b this payload
  map<Address,Document *> addrMap;		///< Map from address to specific inject
public:
  InjectPayloadDynamic(Architecture *g,InjectPayload *base);
  virtual ~InjectPayloadDynamic(void);
  void decodeEntry(Decoder &decoder);
  virtual void inject(InjectContext &context,PcodeEmit &emit) const;
  virtual void decode(Decoder &decoder) { throw LowlevelError("decode not supported for InjectPayloadDynamic"); }
  virtual void printTemplate(ostream &s) const { s << "dynamic"; }
  virtual string getSource(void) const { return "dynamic"; }
};

/// \brief An implementation of an injection library using the internal SLEIGH engine to build payloads
///
/// Payloads from compiler specs and other sources are parsed as SLEIGH syntax and stored
/// internally as InjectPayloadSleigh objects.
class PcodeInjectLibrarySleigh : public PcodeInjectLibrary {
  const SleighBase *slgh;		///< The SLEIGH engine for parsing payloads
  vector<OpBehavior *> inst;		///< P-code behaviors used for p-code scripts
  InjectContextSleigh contextCache;	///< Reusable context for emitting p-code payloads
  InjectPayloadDynamic *forceDebugDynamic(int4 injectid);
  void parseInject(InjectPayload *payload);
protected:
  virtual int4 allocateInject(const string &sourceName,const string &name,int4 type);
  virtual void registerInject(int4 injectid);
public:
  PcodeInjectLibrarySleigh(Architecture *g);	///< Constructor
  virtual void decodeDebug(Decoder &decoder);
  virtual int4 manualCallFixup(const string &name,const string &snippetstring);
  virtual int4 manualCallOtherFixup(const string &name,const string &outname,const vector<string> &inname,
				    const string &snippet);
  virtual InjectContext &getCachedContext(void) { return contextCache; }
  virtual const vector<OpBehavior *> &getBehaviors(void);
};

} // End namespace ghidra
#endif
