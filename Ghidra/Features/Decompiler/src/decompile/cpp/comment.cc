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
#include "comment.hh"
#include "funcdata.hh"

/// \param tp is the set of properties to associate with the comment (or 0 for no properties)
/// \param fad is the Address of the function containing the comment
/// \param ad is the Address of the instruction associated with the comment
/// \param uq is used internally to sub-sort comments at the same address
/// \param txt is the body of the comment
Comment::Comment(uint4 tp,const Address &fad,const Address &ad,int4 uq,const string &txt) :
  type(tp), uniq(uq), funcaddr(fad), addr(ad), text(txt), emitted(false)
{
}

/// The single comment is saved as a \<comment> tag.
/// \param s is the output stream
void Comment::saveXml(ostream &s) const

{
  string tpname = Comment::decodeCommentType(type);
  s << "<comment";
  a_v(s,"type",tpname);
  s << ">\n";
  s << "  <addr";
  funcaddr.getSpace()->saveXmlAttributes(s,funcaddr.getOffset());
  s << "/>\n";
  s << "  <addr";
  addr.getSpace()->saveXmlAttributes(s,addr.getOffset());
  s << "/>\n";
  s << "  <text>";
  xml_escape(s,text.c_str());
  s << "  </text>\n";
  s << "</comment>\n";
}

/// The comment is parsed from a \<comment> tag.
/// \param el is the \<comment> element
/// \param manage is a manager for resolving address space references
void Comment::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  emitted = false;
  type = 0;
  type = Comment::encodeCommentType(el->getAttributeValue("type"));
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  funcaddr = Address::restoreXml(*iter,manage);
  ++iter;
  addr = Address::restoreXml(*iter,manage);
  ++iter;
  if (iter != list.end())
    text = (*iter)->getContent();
}

/// \param name is a string representation of a single comment property
/// \return the enumerated property type
uint4 Comment::encodeCommentType(const string &name)

{
  if (name == "user1")
    return Comment::user1;
  if (name == "user2")
    return Comment::user2;
  if (name == "user3")
    return Comment::user3;
  if (name == "header")
    return Comment::header;
  if (name == "warning")
    return Comment::warning;
  if (name == "warningheader")
    return Comment::warningheader;
  throw LowlevelError("Unknown comment type: "+name);
}

/// \param val is a single comment property
/// \return the string representation of the property
string Comment::decodeCommentType(uint4 val)

{
  switch(val) {
  case user1:
    return "user1";
  case user2:
    return "user2";
  case user3:
    return "user3";
  case header:
    return "header";
  case warning:
    return "warning";
  case warningheader:
    return "warningheader";
  default:
    break;
  }
  throw LowlevelError("Unknown comment type");
}

/// \param a is the first Comment to compare
/// \param b is the second
/// \return \b true is the first is ordered before the second
bool CommentOrder::operator()(const Comment *a,const Comment *b) const

{
  if (a->getFuncAddr() != b->getFuncAddr())
    return (a->getFuncAddr() < b->getFuncAddr());
  if (a->getAddr() != b->getAddr())
    return (a->getAddr() < b->getAddr());
  if (a->getUniq() != b->getUniq())
    return (a->getUniq() < b->getUniq());
  return false;
}

CommentDatabaseInternal::CommentDatabaseInternal(void)
  : CommentDatabase()
{
}

CommentDatabaseInternal::~CommentDatabaseInternal(void)

{
  CommentSet::iterator iter;

  for(iter=commentset.begin();iter!=commentset.end();++iter)
    delete *iter;
}

void CommentDatabaseInternal::clear(void)

{
  CommentSet::iterator iter;

  for(iter=commentset.begin();iter!=commentset.end();++iter)
    delete *iter;
  commentset.clear();
}

void CommentDatabaseInternal::clearType(const Address &fad,uint4 tp)

{
  Comment testcommbeg(0,fad,Address(Address::m_minimal),0,"");
  Comment testcommend(0,fad,Address(Address::m_maximal),65535,"");

  CommentSet::iterator iterbegin = commentset.lower_bound(&testcommbeg);
  CommentSet::iterator iterend = commentset.lower_bound(&testcommend);
  CommentSet::iterator iter;
  while(iterbegin != iterend) {
    iter = iterbegin;
    ++iter;
    if (((*iterbegin)->getType()&tp)!=0) {
      delete (*iterbegin);
      commentset.erase(iterbegin);
    }
    iterbegin = iter;
  }
}

void CommentDatabaseInternal::addComment(uint4 tp,const Address &fad,
					 const Address &ad,
					 const string &txt)
{
  Comment *newcom = new Comment(tp,fad,ad,65535,txt);
  // Find first element greater
  CommentSet::iterator iter = commentset.lower_bound(newcom);
  // turn into last element less than
  if (iter != commentset.begin())
    --iter;
  newcom->uniq = 0;
  if (iter != commentset.end()) {
    if (((*iter)->getAddr() == ad)&&((*iter)->getFuncAddr()==fad))
      newcom->uniq = (*iter)->getUniq() + 1;
  }
  commentset.insert(newcom);
}

bool CommentDatabaseInternal::addCommentNoDuplicate(uint4 tp,const Address &fad,
						    const Address &ad,const string &txt)
{
  Comment *newcom = new Comment(tp,fad,ad,65535,txt);

  // Find first element greater
  CommentSet::iterator iter = commentset.lower_bound(newcom);
  newcom->uniq = 0;		// Set the uniq AFTER the search
  while(iter != commentset.begin()) {
    --iter;
    if (((*iter)->getAddr()==ad)&&((*iter)->getFuncAddr()==fad)) {
      if ((*iter)->getText() == txt) { // Matching text, don't store it
	delete newcom;
	return false;
      }
      if (newcom->uniq == 0)
	newcom->uniq = (*iter)->getUniq() + 1;
    }
    else
      break;
  }
  commentset.insert(newcom);
  return true;
}

void CommentDatabaseInternal::deleteComment(Comment *com)

{
  commentset.erase(com);
  delete com;
}

CommentSet::const_iterator CommentDatabaseInternal::beginComment(const Address &fad) const

{
  Comment testcomm(0,fad,Address(Address::m_minimal),0,"");
  return commentset.lower_bound(&testcomm);
}

CommentSet::const_iterator CommentDatabaseInternal::endComment(const Address &fad) const

{
  Comment testcomm(0,fad,Address(Address::m_maximal),65535,"");
  return commentset.lower_bound(&testcomm);
}

void CommentDatabaseInternal::saveXml(ostream &s) const

{
  CommentSet::const_iterator iter;

  s << "<commentdb>\n";
  for(iter=commentset.begin();iter!=commentset.end();++iter)
    (*iter)->saveXml(s);
  s << "</commentdb>\n";
}

void CommentDatabaseInternal::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  
  for(iter=list.begin();iter!=list.end();++iter) {
    Comment com;
    com.restoreXml(*iter,manage);
    addComment(com.getType(),com.getFuncAddr(),com.getAddr(),com.getText());
  }
}

/// Figure out position of given Comment and initialize its key.
/// \param subsort is a reference to the key to be initialized
/// \param comm is the given Comment
/// \param fd is the function owning the Comment
/// \return \b true if the Comment could be positioned at all
bool CommentSorter::findPosition(Subsort &subsort,Comment *comm,const Funcdata *fd)

{
  if (comm->getType() == 0) return false;
  const Address &fad( fd->getAddress() );
  if (((comm->getType() & (Comment::header | Comment::warningheader))!=0)&&(comm->getAddr() == fad)) {
    // If it is a header comment at the address associated with the beginning of the function
    subsort.setHeader(header_basic);
    return true;
  }

  // Try to find block containing comment
  // Find op at lowest address greater or equal to comment's address
  PcodeOpTree::const_iterator opiter = fd->beginOp(comm->getAddr());
  PcodeOp *backupOp = (PcodeOp *)0;
  if (opiter != fd->endOpAll()) {	// If there is an op at or after the comment
    PcodeOp *op = (*opiter).second;
    BlockBasic *block = op->getParent();
    if (block == (BlockBasic *)0)
      throw LowlevelError("Dead op reaching CommentSorter");
    if (block->contains(comm->getAddr())) { // If the op's block contains the address
      // Associate comment with this op
      subsort.setBlock(block->getIndex(), (uint4)op->getSeqNum().getOrder());
      return true;
    }
    if (comm->getAddr() == op->getAddr())
      backupOp = op;
  }
  if (opiter != fd->beginOpAll()) {	// If there is a previous op
    --opiter;
    PcodeOp *op = (*opiter).second;
    BlockBasic *block = op->getParent();
    if (block == (BlockBasic *)0)
      throw LowlevelError("Dead op reaching CommentSorter");
    if (block->contains(comm->getAddr())) { // If the op's block contains the address
      // Treat the comment as being in this block at the very end
      subsort.setBlock(block->getIndex(),0xffffffff);
      return true;
    }
  }
  if (backupOp != (PcodeOp *)0) {
    // Its possible the op migrated from its original basic block.
    // Since the address matches exactly, hang the comment on it
    subsort.setBlock(backupOp->getParent()->getIndex(),(uint4)backupOp->getSeqNum().getOrder());
    return true;
  }
  if (fd->beginOpAll() == fd->endOpAll()) {	// If there are no ops at all
    subsort.setBlock(0,0);	// Put comment at the beginning of the first block
    return true;
  }
  if (displayUnplacedComments) {
    subsort.setHeader(header_unplaced);
    return true;
  }
  return false;		// Basic block containing comment has been excised
}

/// \brief Collect and sort comments specific to the given function.
///
/// Only keep comments matching one of a specific set of properties
/// \param tp is the set of properties (may be zero)
/// \param fd is the given function
/// \param db is the container of comments to collect from
/// \param displayUnplaced is \b true if unplaced comments should be displayed in the header
void CommentSorter::setupFunctionList(uint4 tp,const Funcdata *fd,const CommentDatabase &db,bool displayUnplaced)
{
  commmap.clear();
  displayUnplacedComments = displayUnplaced;
  if (tp == 0) return;
  const Address &fad( fd->getAddress() );
  CommentSet::const_iterator iter = db.beginComment(fad);
  CommentSet::const_iterator lastiter = db.endComment(fad);
  Subsort subsort;

  subsort.pos = 0;

  while(iter != lastiter) {
    Comment *comm = *iter;
    if (findPosition(subsort, comm, fd)) {
      comm->setEmitted(false);
      commmap[ subsort ] = comm;
      subsort.pos += 1;		// Advance the uniqueness counter
    }
    ++iter;
  }
}

/// This will generally get called with the root p-code op of a statement
/// being emitted by the decompiler. This establishes a key value within the
/// basic block, so it is known where to stop emitting comments within the
/// block for emitting the statement.
/// \param op is the p-code representing the root of a statement
void CommentSorter::setupOpList(const PcodeOp *op)

{
  if (op == (const PcodeOp *)0) { // If NULL op
    opstop = stop;		// pick up any remaining comments in this basic block
    return;
  }
  Subsort subsort;
  subsort.index = op->getParent()->getIndex();
  subsort.order = (uint4)op->getSeqNum().getOrder();
  subsort.pos = 0xffffffff;
  opstop = commmap.upper_bound(subsort);
}

/// Find iterators that bound everything in the basic block
///
/// \param bl is the basic block
void CommentSorter::setupBlockList(const FlowBlock *bl)

{
  Subsort subsort;
  subsort.index = bl->getIndex();
  subsort.order = 0;
  subsort.pos = 0;
  start = commmap.lower_bound(subsort);
  subsort.order = 0xffffffff;
  subsort.pos = 0xffffffff;
  stop = commmap.upper_bound(subsort);
}

/// Header comments are grouped together. Set up iterators.
/// \param headerType selects either \b header_basic or \b header_unplaced comments
void CommentSorter::setupHeader(uint4 headerType)

{
  Subsort subsort;
  subsort.index = -1;
  subsort.order = headerType;
  subsort.pos = 0;
  start = commmap.lower_bound(subsort);
  subsort.pos = 0xffffffff;
  opstop = commmap.upper_bound(subsort);
}
