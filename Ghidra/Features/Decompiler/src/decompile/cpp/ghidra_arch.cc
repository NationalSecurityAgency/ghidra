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
#include "ghidra_context.hh"
#include "loadimage_ghidra.hh"
#include "database_ghidra.hh"
#include "ghidra_translate.hh"
#include "typegrp_ghidra.hh"
#include "comment_ghidra.hh"
#include "string_ghidra.hh"
#include "cpool_ghidra.hh"
#include "inject_ghidra.hh"

namespace ghidra {

//AttributeId ATTRIB_BADDATA = AttributeId("baddata",145);

ElementId ELEM_COMMAND_ISNAMEUSED = ElementId("command_isnameused",239);
ElementId ELEM_COMMAND_GETBYTES = ElementId("command_getbytes",240);
ElementId ELEM_COMMAND_GETCALLFIXUP = ElementId("command_getcallfixup",241);
ElementId ELEM_COMMAND_GETCALLMECH = ElementId("command_getcallmech",242);
ElementId ELEM_COMMAND_GETCALLOTHERFIXUP = ElementId("command_getcallotherfixup",243);
ElementId ELEM_COMMAND_GETCODELABEL = ElementId("command_getcodelabel",244);
ElementId ELEM_COMMAND_GETCOMMENTS = ElementId("command_getcomments",245);
ElementId ELEM_COMMAND_GETCPOOLREF = ElementId("command_getcpoolref",246);
ElementId ELEM_COMMAND_GETDATATYPE = ElementId("command_getdatatype",247);
ElementId ELEM_COMMAND_GETEXTERNALREF = ElementId("command_getexternalref",248);
ElementId ELEM_COMMAND_GETMAPPEDSYMBOLS = ElementId("command_getmappedsymbols",249);
ElementId ELEM_COMMAND_GETNAMESPACEPATH = ElementId("command_getnamespacepath",250);
ElementId ELEM_COMMAND_GETPCODE = ElementId("command_getpcode",251);
ElementId ELEM_COMMAND_GETPCODEEXECUTABLE = ElementId("command_getpcodeexecutable",252);
ElementId ELEM_COMMAND_GETREGISTER = ElementId("command_getregister",253);
ElementId ELEM_COMMAND_GETREGISTERNAME = ElementId("command_getregistername",254);
ElementId ELEM_COMMAND_GETSTRINGDATA = ElementId("command_getstringdata",255);
ElementId ELEM_COMMAND_GETTRACKEDREGISTERS = ElementId("command_gettrackedregisters",256);
ElementId ELEM_COMMAND_GETUSEROPNAME = ElementId("command_getuseropname",257);

/// Catch the signal so the OS doesn't pop up a dialog
/// \param sig is the OS signal (should always be SIGSEGV)
void ArchitectureGhidra::segvHandler(int4 sig)

{
  exit(1);	// Just die - prevents OS from popping-up a dialog
}

/// All communications between the Ghidra client and the decompiler are surrounded
/// by alignment bursts. A burst is 1 or more zero bytes followed by
/// an 0x01 byte, then followed by a code byte.
/// Open alignment (as in open paren) is even.  Close alignment is odd.
/// Code bytes are as follows:
///   - Command                 open=2 close=3
///   - Query                   open=4 close=5
///   - Command response        open=6 close=7
///   - Query response          open=8 close=9
///   - Exception               open=a close=b
///   - Byte stream             open=c close=d
///   - String stream           open=e close=f
///
/// The protocol is as follows:
///   - ghidra sends a command
///      -  [ decompiler sends a query
///      -    ghidra sends a query response  ]   zero or more occurences
///   - decompiler sends a command response
///
/// Commands, queries, and responses all consist of zero or more string streams or byte
/// streams.
///
/// In place of any response an exception can be sent.
/// The decompiler can interrupt a command response with a query or exception
///   once the query is finished the response picks up where it left off
///   an exception however permanently cancels the query.
/// Ghidra cannot interrupt either of its responses.
/// \param s is the input stream from the client
/// \return the command code
int4 ArchitectureGhidra::readToAnyBurst(istream &s)

{
  int4 c;

  for(;;) {
    do {
      c = s.get();
    } while(c>0);
    while(c==0) {
      c = s.get();
    }
    if (c==1) {
      c = s.get();
      return c;
    }
    if (c<0)			// If pipe closed, our parent process is probably dead
      exit(1);			// So we exit to avoid a runaway process
  }
}

/// Read the string protocol start, a single character, then the protocol end.
/// If the character is a 't', return \b true, otherwise \b false.
/// \param s is the input stream from the client
/// \return the passed back boolean value
bool ArchitectureGhidra::readBoolStream(istream &s)

{
  int4 c;
  bool res;

  int4 type = readToAnyBurst(s);
  if (type != 14) throw JavaError("alignment","Expecting string");
  c = s.get();
  res = (c == 't');
  c = s.get();
  while(c==0) {
    c = s.get();
  }
  if (c==1) {
    c = s.get();
    if (c == 15)
      return res;
  }
  if (c<0)			// If pipe closed, our parent process is probably dead
    exit(1);			// So we exit to avoid a runaway process
  throw JavaError("alignment","Expecting string terminator");
}

/// Characters are read up to the next protocol marked and placed into a string.
/// The protocol marker is consumed and must indicate the end of a string
/// or an exception is thrown.
/// \param s is the input stream from the client
/// \param res will hold the string
void ArchitectureGhidra::readStringStream(istream &s,string &res)

{
  int4 c;

  int4 type = readToAnyBurst(s);
  if (type != 14) throw JavaError("alignment","Expecting string");
  c = s.get();
  while(c > 0) {
    res += (char)c;
    c = s.get();
  }
  while(c==0) {
    c = s.get();
  }
  if (c==1) {
    c = s.get();
    if (c == 15) return;
  }
  if (c<0)			// If pipe closed, our parent process is probably dead
    exit(1);			// So we exit to avoid a runaway process
  throw JavaError("alignment","Expecting string terminator");
}

/// The method expects to see protocol markers indicating a string from the client,
/// otherwise it throws and exception.  The string is read into the given stream decoder.
/// \param s is the input stream from the client.
/// \param decoder is the given stream decoder that will hold the result
/// \return \b true if a response was received
bool ArchitectureGhidra::readStringStream(istream &s,Decoder &decoder)

{
  int4 type = readToAnyBurst(s);
  if (type==14) {
    decoder.ingestStream(s);
    type = readToAnyBurst(s);
    if (type!=15)
      throw JavaError("alignment","Expecting XML string end");
    return true;
  }
  if ((type&1)==1)
    return false;
  throw JavaError("alignment","Expecting string or end of query response");
}

/// Write out a string with correct protocol markers
/// \param s is the output stream to the client
/// \param msg is the string to send
void ArchitectureGhidra::writeStringStream(ostream &s,const string &msg)

{
  s.write("\000\000\001\016",4);
  s << msg;
  s.write("\000\000\001\017",4);
}

/// Consume the query response header. If it indicates an exception,
/// read details of the exception and throw JavaError.
/// \param s is the input stream from the client
void ArchitectureGhidra::readToResponse(istream &s)

{
  int4 type = readToAnyBurst(s);
  if (type==8) return;
  if (type==10) {
    string excepttype,message;
    readStringStream(s,excepttype);
    readStringStream(s,message);
    type = readToAnyBurst(s);	// This should be the exception terminator
    throw JavaError(excepttype,message);
  }
  throw JavaError("alignment","Expecting query response");
}

/// Read the next protocol marker. If it does not indicate the end of
/// a query response, throw an exception
/// \param s is the input stream from the client
void ArchitectureGhidra::readResponseEnd(istream &s)

{
  int4 type = readToAnyBurst(s);
  if (type != 9)
    throw JavaError("alignment","Expecting end of query response");
}

/// Read up to the beginning of a query response, check for an
/// exception record, otherwise pass back an element for decoding.
/// \param s is the input stream from the client
/// \param decoder is the stream decoder that will hold the result
/// \return \b true if we received a valid response
bool ArchitectureGhidra::readAll(istream &s,Decoder &decoder)

{
  readToResponse(s);
  if (readStringStream(s,decoder)) {
    readResponseEnd(s);
    return true;
  }
  return false;
}

/// \brief Send an exception message to the Ghidra client
///
/// This generally called because of some sort of alignment issue in the
/// message protocol and lets the client know to abort (and hopefully resync)
/// \param s is the output stream to the client
/// \param tp is the type of exception
/// \param msg is the exception message
void ArchitectureGhidra::passJavaException(ostream &s,const string &tp,const string &msg)

{
  s.write("\000\000\001\012",4);
  writeStringStream(s,tp);
  writeStringStream(s,msg);
  s.write("\000\000\001\013",4);
}

void ArchitectureGhidra::buildSpecFile(DocumentStorage &store)

{ // Spec files are passed as XML strings from GHIDRA
  istringstream pstream(pspecxml); // Convert string to stream
  Document *doc = store.parseDocument(pstream); // parse stream
  store.registerTag(doc->getRoot());
  
  istringstream cstream(cspecxml);
  doc = store.parseDocument(cstream);
  store.registerTag(doc->getRoot());

  istringstream tstream(tspecxml);
  doc = store.parseDocument(tstream);
  store.registerTag(doc->getRoot());

  istringstream corestream(corespecxml);
  doc = store.parseDocument(corestream);
  store.registerTag(doc->getRoot());

  pspecxml.clear();		// Strings aren't used again free memory
  cspecxml.clear();
  tspecxml.clear();
  corespecxml.clear();
}

void ArchitectureGhidra::postSpecFile(void)

{
  Architecture::postSpecFile();
  ScopeGhidra *scopeGhidra = (ScopeGhidra *)symboltab->getGlobalScope();
  scopeGhidra->lockDefaultProperties();
}

void ArchitectureGhidra::buildLoader(DocumentStorage &store)

{
  loader = new LoadImageGhidra(this);
}

PcodeInjectLibrary *ArchitectureGhidra::buildPcodeInjectLibrary(void)

{
  return new PcodeInjectLibraryGhidra(this);
}

Translate *ArchitectureGhidra::buildTranslator(DocumentStorage &store)

{
  return new GhidraTranslate(this);
}

Scope *ArchitectureGhidra::buildDatabase(DocumentStorage &store)

{
  symboltab = new Database(this,false);
  Scope *globalscope = new ScopeGhidra(this);
  symboltab->attachScope(globalscope,(Scope *)0);
  return globalscope;
}

void ArchitectureGhidra::buildTypegrp(DocumentStorage &store)

{
  const Element *el = store.getTag("coretypes");
  types = new TypeFactoryGhidra(this);
  if (el != (const Element *)0) {
    XmlDecode decoder(this,el);
    types->decodeCoreTypes(decoder);
  }
  else {
    // Put in the core types
    types->setCoreType("void",1,TYPE_VOID,false);
    types->setCoreType("bool",1,TYPE_BOOL,false);
    types->setCoreType("byte",1,TYPE_UINT,false);
    types->setCoreType("word",2,TYPE_UINT,false);
    types->setCoreType("dword",4,TYPE_UINT,false);
    types->setCoreType("qword",8,TYPE_UINT,false);
    types->setCoreType("char",1,TYPE_INT,true);
    types->setCoreType("sbyte",1,TYPE_INT,false);
    types->setCoreType("sword",2,TYPE_INT,false);
    types->setCoreType("sdword",4,TYPE_INT,false);
    types->setCoreType("sqword",8,TYPE_INT,false);
    types->setCoreType("float",4,TYPE_FLOAT,false);
    types->setCoreType("float8",8,TYPE_FLOAT,false);
    types->setCoreType("float16",16,TYPE_FLOAT,false);
    types->setCoreType("undefined",1,TYPE_UNKNOWN,false);
    types->setCoreType("undefined2",2,TYPE_UNKNOWN,false);
    types->setCoreType("undefined4",4,TYPE_UNKNOWN,false);
    types->setCoreType("undefined8",8,TYPE_UNKNOWN,false);
    types->setCoreType("code",1,TYPE_CODE,false);
    types->setCoreType("wchar",2,TYPE_INT,true);
    types->cacheCoreTypes();
  }
}

void ArchitectureGhidra::buildCommentDB(DocumentStorage &store)

{
  commentdb = new CommentDatabaseGhidra(this);
}

void ArchitectureGhidra::buildStringManager(DocumentStorage &store)

{
  stringManager = new GhidraStringManager(this,2048);
}

void ArchitectureGhidra::buildConstantPool(DocumentStorage &store)

{
  cpool = new ConstantPoolGhidra(this);
}

void ArchitectureGhidra::buildContext(DocumentStorage &store)

{
  context = new ContextGhidra(this);
}

void ArchitectureGhidra::buildSymbols(DocumentStorage &store)

{
  const Element *symtag = store.getTag(ELEM_DEFAULT_SYMBOLS.getName());
  if (symtag == (const Element *)0) return;
  XmlDecode decoder(this,symtag);
  uint4 el = decoder.openElement(ELEM_DEFAULT_SYMBOLS);
  while(decoder.peekElement() != 0) {
    uint4 subel = decoder.openElement(ELEM_SYMBOL);
    string addrString;
    string name;
    int4 size = 0;
    int4 volatileState = -1;
    for(;;) {
      uint4 attribId = decoder.getNextAttributeId();
      if (attribId == 0) break;
      if (attribId == ATTRIB_NAME)
	name = decoder.readString();
      else if (attribId == ATTRIB_ADDRESS) {
	addrString = decoder.readString();
      }
      else if (attribId == ATTRIB_VOLATILE) {
	volatileState = decoder.readBool() ? 1 : 0;
      }
      else if (attribId == ATTRIB_SIZE)
	size = decoder.readSignedInteger();
    }
    decoder.closeElement(subel);
    if (name.size() == 0)
      throw LowlevelError("Missing name attribute in <symbol> element");
    if (addrString.size() == 0)
      throw LowlevelError("Missing address attribute in <symbol> element");

    // Currently we only use the volatile attribute on pspec symbols and let Ghidra
    // feed the global symbol to the decompiler on a per function basic.
    if (volatileState < 0)
      continue;
    Address addr = parseAddressSimple(addrString);
    if (size == 0)
      size = addr.getSpace()->getWordSize();
    Range range(addr.getSpace(),addr.getOffset(),addr.getOffset() + (size-1));
    if (volatileState == 0)
      symboltab->clearPropertyRange(Varnode::volatil, range);
    else
      symboltab->setPropertyRange(Varnode::volatil, range);
  }
  decoder.closeElement(el);
}

void ArchitectureGhidra::resolveArchitecture(void)

{
  archid = "ghidra";
}

/// Ask the Ghidra client if it knows about a specific processor register.
/// The client responds with a \<addr> element describing the storage
/// location of the register.
/// \param regname is the name to query for
/// \param decoder is the stream decoder that will hold the result
/// \return \b true if the query completed successfully
bool ArchitectureGhidra::getRegister(const string &regname,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETREGISTER);
  encoder.writeString(ATTRIB_NAME, regname);
  encoder.closeElement(ELEM_COMMAND_GETREGISTER);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

/// Given a storage location and size, ask the Ghidra client if it knows of
/// a register that occupies those bytes. The register name is passed back.
/// The name may not exactly match the given memory range, it may contain it.
/// \param vndata is the location and size
/// \return the register name or ""
string ArchitectureGhidra::getRegisterName(const VarnodeData &vndata)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  Address addr(vndata.space,vndata.offset);
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETREGISTERNAME);
  addr.encode(encoder,vndata.size);
  encoder.closeElement(ELEM_COMMAND_GETREGISTERNAME);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  readToResponse(sin);
  string res;
  readStringStream(sin,res);
  readResponseEnd(sin);
  return res;
}

/// The Ghidra client will pass back a description of registers that have
/// known values at the given address. The response is generally a
/// \<tracked_pointset> which contains \<set> children which contains
/// a storage location and value.
/// \param addr is the given address
/// \param decoder is the stream decoder which will hold the result
/// \return \b true if the query completed successfully
bool ArchitectureGhidra::getTrackedRegisters(const Address &addr,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETTRACKEDREGISTERS);
  addr.encode(encoder);
  encoder.closeElement(ELEM_COMMAND_GETTRACKEDREGISTERS);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

/// The first operand to a CALLOTHER op indicates the specific user-defined op.
/// This method queries the Ghidra client and passes back the name of the op.
/// \param index is the value of the CALLOTHER operand
/// \return the recovered name or ""
string ArchitectureGhidra::getUserOpName(int4 index)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETUSEROPNAME);
  encoder.writeSignedInteger(ATTRIB_INDEX, index);
  encoder.closeElement(ELEM_COMMAND_GETUSEROPNAME);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  readToResponse(sin);
  string res;
  readStringStream(sin,res);
  readResponseEnd(sin);
  return res;
}

/// Get a description of all the p-code ops for the instruction at the given address.
/// \param addr is the address of the instruction
/// \param decoder is the stream decoder for holding the result
/// \return true if the request is successful and ops are ready to be decoded
bool ArchitectureGhidra::getPcode(const Address &addr,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETPCODE);
  addr.encode(encoder);
  encoder.closeElement(ELEM_COMMAND_GETPCODE);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

/// The Ghidra client will pass back a \<symbol> element, \<function> element, or some
/// other related Symbol information, in the given stream decoder. If there is no symbol at the address
/// the client will return a \<hole> element describing the size of the
/// memory region that is free of symbols.
/// \param addr is the given address
/// \param decoder is the given stream decoder that will hold the result
/// \return \b true if the query completes successfully
bool ArchitectureGhidra::getMappedSymbolsXML(const Address &addr,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETMAPPEDSYMBOLS);
  addr.encode(encoder);
  encoder.closeElement(ELEM_COMMAND_GETMAPPEDSYMBOLS);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

/// This asks the Ghidra client to resolve an \e external \e reference.
/// This is an address for which the client holds a reference to a function
/// that is elsewhere in memory or not in memory at all.  The client
/// should unravel the reference from the given address and pass back either
/// a \<function> element describing the referred to function symbol or
/// a \<hole> element if the reference can't be resolved.
/// \param addr is the given address
/// \param decoder is the stream decoder that will hold the result
/// \return \b true if the query completes successfully
bool ArchitectureGhidra::getExternalRef(const Address &addr,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETEXTERNALREF);
  addr.encode(encoder);
  encoder.closeElement(ELEM_COMMAND_GETEXTERNALREF);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

/// Ask the Ghidra client to list all namespace elements between the global root
/// and the namespace of the given id. The client will pass back a \<parent> element with
/// a \<val> child for each namespace in the path, in the given stream decoder
/// \param id is the given id of the namespace to resolve
/// \param decoder is the given stream decoder that will hold the result
/// \return \b true if the query completed successfully
bool ArchitectureGhidra::getNamespacePath(uint8 id,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETNAMESPACEPATH);
  encoder.writeUnsignedInteger(ATTRIB_ID, id);
  encoder.closeElement(ELEM_COMMAND_GETNAMESPACEPATH);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

bool ArchitectureGhidra::isNameUsed(const string &nm,uint8 startId,uint8 stopId)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_ISNAMEUSED);
  encoder.writeString(ATTRIB_NAME, nm);
  encoder.writeUnsignedInteger(ATTRIB_FIRST, startId);
  encoder.writeUnsignedInteger(ATTRIB_LAST, stopId);
  encoder.closeElement(ELEM_COMMAND_ISNAMEUSED);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  readToResponse(sin);
  bool res = readBoolStream(sin);
  readResponseEnd(sin);
  return res;
}

/// Get the name of the primary symbol at the given address.
/// This is used to fetch within function \e labels. Only a name is returned.
/// \param addr is the given address
/// \return the symbol name or ""
string ArchitectureGhidra::getCodeLabel(const Address &addr)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETCODELABEL);
  addr.encode(encoder);
  encoder.closeElement(ELEM_COMMAND_GETCODELABEL);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  readToResponse(sin);
  string res;
  readStringStream(sin,res);
  readResponseEnd(sin);
  return res;
}

/// The Ghidra client will pass back a \<type> element giving details
/// about the data-type.
/// \param name is the name of the data-type
/// \param id is a unique id associated with the data-type, pass 0 if unknown
/// \param decoder is the stream decoder that will hold the result
/// \return \b true if the query completed successfully
bool ArchitectureGhidra::getDataType(const string &name,uint8 id,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETDATATYPE);
  encoder.writeString(ATTRIB_NAME, name);
  encoder.writeSignedInteger(ATTRIB_ID, id);
  encoder.closeElement(ELEM_COMMAND_GETDATATYPE);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

/// Ask Ghidra client for all comments associated with one function.
/// The caller must provide the sub-set of properties (Comment::comment_type) for
/// the query to match.  A \<commentdb> element with  \<comment> element child for each comment found
/// will be passed back in the given stream decoder.
/// \param fad is the address of the function to query
/// \param flags specifies the properties the query will match (must be non-zero)
/// \param decoder is the given stream decoder that will hold the result
/// \return \b true if the query completed successfully
bool ArchitectureGhidra::getComments(const Address &fad,uint4 flags,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETCOMMENTS);
  encoder.writeUnsignedInteger(ATTRIB_TYPE, flags);
  fad.encode(encoder);
  encoder.closeElement(ELEM_COMMAND_GETCOMMENTS);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

/// The Ghidra client is queried for a range of bytes, which are returned
/// in the given array. This method throws a DataUnavailError if the provided
/// address doesn't make sense.
/// \param buf is the preallocated array in which to store the bytes
/// \param size is the number of bytes requested
/// \param inaddr is the address in the LoadImage from which to grab bytes
void ArchitectureGhidra::getBytes(uint1 *buf,int4 size,const Address &inaddr)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETBYTES);
  inaddr.encode(encoder,size);
  encoder.closeElement(ELEM_COMMAND_GETBYTES);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  readToResponse(sin);
  int4 type = readToAnyBurst(sin);
  if (type == 12) {
    uint1 *dblbuf = new uint1[size * 2];
    sin.read((char *)dblbuf,size*2);
    for (int4 i=0; i < size; i++) {
      buf[i] = ((dblbuf[i*2]-'A') << 4) | (dblbuf[i*2 + 1]-'A');
    }
    delete [] dblbuf;
  }
  else if ((type&1)==1) {
    ostringstream errmsg;
    errmsg << "GHIDRA has no data in the loadimage at " << inaddr.getShortcut();
    inaddr.printRaw(errmsg);
    throw DataUnavailError(errmsg.str());
  }
  else
    throw JavaError("alignment","Expecting bytes or end of query response");
  type = readToAnyBurst(sin);
  if (type != 13)
    throw JavaError("alignment","Expecting byte alignment end");
  readResponseEnd(sin);
}

/// \brief Get string data at a specific address
///
/// The data is always returned as a sequence of bytes in UTF-8 format. The in-memory form of
/// the string may be different than UTF-8 but is always translated into UTF-8 by this method.
/// The caller can inform the in-memory format of the string by specifying a specific string
/// data-type.  A maximum number of bytes to return is specified.  If this is exceeded, a boolean
/// reference is set to \b true.
/// \param buffer will hold the string bytes in UTF-8 format
/// \param addr is program Address that holds the string data in memory
/// \param ct is string data-type expected
/// \param maxBytes is the maximum number of bytes to return
/// \param isTrunc is the boolean reference indicating whether the data is truncated
void ArchitectureGhidra::getStringData(vector<uint1> &buffer,const Address &addr,Datatype *ct,int4 maxBytes,bool &isTrunc)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETSTRINGDATA);
  encoder.writeSignedInteger(ATTRIB_MAXSIZE, maxBytes);
  encoder.writeString(ATTRIB_TYPE,ct->getName());
  encoder.writeUnsignedInteger(ATTRIB_ID, ct->getId());
  addr.encode(encoder);
  encoder.closeElement(ELEM_COMMAND_GETSTRINGDATA);
  sout.write("\000\000\001\017",4);

  sout.write("\000\000\001\005",4);
  sout.flush();

  readToResponse(sin);
  int4 type = readToAnyBurst(sin);
  if (type == 12) {
    int4 c = sin.get();
    uint4 size = (c-0x20);
    c = sin.get();
    size ^= ((c-0x20)<<6);
    isTrunc = (sin.get() != 0);
    buffer.reserve(size);
    uint1 *dblbuf = new uint1[size * 2];
    sin.read((char *)dblbuf,size*2);
    for (int4 i=0; i < size; i++) {
      buffer.push_back(((dblbuf[i*2]-'A') << 4) | (dblbuf[i*2 + 1]-'A'));
    }
    delete [] dblbuf;
    type = readToAnyBurst(sin);
    if (type != 13)
      throw JavaError("alignment","Expecting byte alignment end");
    type = readToAnyBurst(sin);
  }
  if ((type&1)==1) {
    // Leave the buffer empty
  }
  else
    throw JavaError("alignment","Expecting end of query response");
}

/// \brief Retrieve p-code to inject for a specific context
///
/// The particular injection is named and is of one of the types:
///   - CALLFIXUP_TYPE
///   - CALLOTHERFIXUP_TYPE
///   - CALLMECHANISM_TYPE
///   - EXECUTABLEPCODE_TYPE
///
/// This and additional context is provided to the Ghidra client which passes back
/// an \<inst> element containing individual \<op> tags corresponding to individual p-code ops.
/// \param name is the name of the injection
/// \param type is the type of injection
/// \param con is the context object
/// \param decoder is the stream decoder which will hold the result
/// \return \b true if the query completed successfully
bool ArchitectureGhidra::getPcodeInject(const string &name,int4 type,const InjectContext &con,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4);
  PackedEncode encoder(sout);
  if (type == InjectPayload::CALLFIXUP_TYPE) {
    encoder.openElement(ELEM_COMMAND_GETCALLFIXUP);
    encoder.writeString(ATTRIB_NAME, name);
    con.encode(encoder);
    encoder.closeElement(ELEM_COMMAND_GETCALLFIXUP);
  }
  else if (type == InjectPayload::CALLOTHERFIXUP_TYPE) {
    encoder.openElement(ELEM_COMMAND_GETCALLOTHERFIXUP);
    encoder.writeString(ATTRIB_NAME, name);
    con.encode(encoder);
    encoder.closeElement(ELEM_COMMAND_GETCALLOTHERFIXUP);
  }
  else if (type == InjectPayload::CALLMECHANISM_TYPE) {
    encoder.openElement(ELEM_COMMAND_GETCALLMECH);
    encoder.writeString(ATTRIB_NAME, name);
    con.encode(encoder);
    encoder.closeElement(ELEM_COMMAND_GETCALLMECH);
 }
  else {
    encoder.openElement(ELEM_COMMAND_GETPCODEEXECUTABLE);
    encoder.writeString(ATTRIB_NAME, name);
    con.encode(encoder);
    encoder.closeElement(ELEM_COMMAND_GETPCODEEXECUTABLE);
  }

  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

/// The Ghidra client is provided a sequence of 1 or more integer values
/// extracted from a CPOOLREF op. A description of the constant pool record referenced by the integer(s)
/// is passed back in the given stream decoder, or an exception is thrown if the record isn't properly referenced.
/// \param refs is an array of 1 or more integer values referencing a constant pool record
/// \param decoder is the given stream decoder that will hold the result
/// \return \b true if the query completed successfully
bool ArchitectureGhidra::getCPoolRef(const vector<uintb> &refs,Decoder &decoder)

{
  sout.write("\000\000\001\004",4);
  sout.write("\000\000\001\016",4); // Beginning of string header
  PackedEncode encoder(sout);
  encoder.openElement(ELEM_COMMAND_GETCPOOLREF);
  encoder.writeSignedInteger(ATTRIB_SIZE, refs.size());
  for(int4 i=0;i<refs.size();++i) {
    encoder.openElement(ELEM_VALUE);
    encoder.writeUnsignedInteger(ATTRIB_CONTENT, refs[i]);
    encoder.closeElement(ELEM_VALUE);
  }
  encoder.closeElement(ELEM_COMMAND_GETCPOOLREF);
  sout.write("\000\000\001\017",4);
  sout.write("\000\000\001\005",4);
  sout.flush();

  return readAll(sin,decoder);
}

void ArchitectureGhidra::printMessage(const string &message) const

{
  warnings += '\n'+message;
}

/// \brief Construct given specification files and i/o streams
///
/// \param pspec is the processor specification presented as an XML string
/// \param cspec is the compiler specification presented as an XML string
/// \param tspec is a stripped down form of the SLEIGH specification presented as an XML string
/// \param corespec is a list of core data-types presented as a \<coretypes> XML tag
/// \param i is the input stream from the Ghidra client
/// \param o is the output stream to the Ghidra client
ArchitectureGhidra::ArchitectureGhidra(const string &pspec,const string &cspec,const string &tspec,
				       const string &corespec,istream &i,ostream &o)
  : Architecture(), sin(i), sout(o)

{
  print->setMarkup(true);
  print->setOutputStream(&sout);
  pspecxml = pspec;
  cspecxml = cspec;
  tspecxml = tspec;
  corespecxml = corespec;
  sendsyntaxtree = true;	// Default to sending everything
  sendCcode = true;
  sendParamMeasures = false;
}

bool ArchitectureGhidra::isDynamicSymbolName(const string &nm)

{
  if (nm.size() < 8) return false;	// 4 characters of prefix, at least 4 of address
  if (nm[3] != '_') return false;
  if (nm[0]=='F' && nm[1]=='U' && nm[2]=='N') {
  }
  else if (nm[0]=='D' && nm[1]=='A' && nm[2]=='T') {
  }
  else {
    return false;
  }
  for(int4 i=nm.size()-4;i<nm.size();++i) {
    char c = nm[i];
    if (c>='0' && c<='9') continue;
    if (c>='a' && c<='f') continue;
    return false;
  }
  return true;
}

} // End namespace ghidra
