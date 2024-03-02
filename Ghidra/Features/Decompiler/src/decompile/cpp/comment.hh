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
/// \file comment.hh
/// \brief A database interface for high-level language comments

#ifndef __COMMENT_HH__
#define __COMMENT_HH__

#include "address.hh"

namespace ghidra {

class FlowBlock;
class PcodeOp;
class Funcdata;

extern ElementId ELEM_COMMENT;			///< Marshaling element \<comment>
extern ElementId ELEM_COMMENTDB;		///< Marshaling element \<commentdb>
extern ElementId ELEM_TEXT;		///< Marshaling element \<text>

/// \brief A comment attached to a specific function and code address
///
/// Things contains the actual character data of the comment. It is
/// fundamentally attached to a specific function and to the address of
/// an instruction (within the function's body). Comments
/// can be categorized as a \e header (or not) depending on whether
/// it should be displayed as part of the general description of the
/// function or not. Other properties can be assigned to a comment, to
/// allow the user to specify the subset of all comments they want to display.
class Comment {
  friend class CommentDatabaseInternal;
  uint4 type;			///< The properties associated with the comment
  int4 uniq;			///< Sub-identifier for uniqueness
  Address funcaddr;		///< Address of the function containing the comment
  Address addr;			///< Address associated with the comment
  string text;			///< The body of the comment
  mutable bool emitted;		///< \b true if this comment has already been emitted
public:
  /// \brief Possible properties associated with a comment
  enum comment_type {
    user1 = 1,			///< The first user defined property
    user2 = 2,			///< The second user defined property
    user3 = 4,			///< The third user defined property
    header = 8,			///< The comment should be displayed in the function header
    warning = 16,		///< The comment is auto-generated to alert the user
    warningheader = 32		///< The comment is auto-generated and should be in the header
  };
  Comment(uint4 tp,const Address &fad,const Address &ad,int4 uq,const string &txt);	///< Constructor
  Comment(void) {} 	///< Constructor for use with decode
  void setEmitted(bool val) const { emitted = val; }		///< Mark that \b this comment has been emitted
  bool isEmitted(void) const { return emitted; }		///< Return \b true if \b this comment is already emitted
  uint4 getType(void) const { return type; }			///< Get the properties associated with the comment
  const Address &getFuncAddr(void) const { return funcaddr; }	///< Get the address of the function containing the comment
  const Address &getAddr(void) const { return addr; }		///< Get the address to which the instruction is attached
  int4 getUniq(void) const { return uniq; }			///< Get the sub-sorting index
  const string &getText(void) const { return text; }		///< Get the body of the comment
  void encode(Encoder &encoder) const;				///< Encode the comment to a stream
  void decode(Decoder &decoder);				///< Decode the comment from a stream
  static uint4 encodeCommentType(const string &name);		///< Convert name string to comment property
  static string decodeCommentType(uint4 val);			///< Convert comment property to string
};

/// \brief Compare two Comment pointers
///
/// Comments are ordered first by function, then address,
/// then the sub-sort index.
struct CommentOrder {
  bool operator()(const Comment *a,const Comment *b) const;	///< Comparison operator
};

typedef set<Comment *,CommentOrder> CommentSet;		///< A set of comments sorted by function and address

/// \brief An interface to a container of comments
///
/// Comments can be added (and removed) from a database, keying
/// on the function and address the Comment is attached to.
/// The interface can generate a \e begin and \e end iterator covering
/// all Comment objects for a single function.
class CommentDatabase {
public:
  CommentDatabase(void) {}		///< Constructor
  virtual ~CommentDatabase(void) {}	///< Destructor
  virtual void clear(void)=0;		///< Clear all comments from this container

  /// \brief Clear all comments matching (one of) the indicated types
  ///
  /// Clearing is restricted to comments belonging to a specific function and matching
  /// at least one of the given properties
  /// \param fad is the address of the owning function
  /// \param tp is a set of one or more properties
  virtual void clearType(const Address &fad,uint4 tp)=0;

  /// \brief Add a new comment to the container
  ///
  /// \param tp is a set of properties to associate with the new comment (may be zero)
  /// \param fad is the address of the function to which the comment belongs
  /// \param ad is the address to which the comment is attached
  /// \param txt is the body of the comment
  virtual void addComment(uint4 tp,const Address &fad,
			  const Address &ad,const string &txt)=0;

  /// \brief Add a new comment to the container, making sure there is no duplicate
  ///
  /// If there is already a comment at the same address with the same body, no
  /// new comment is added.
  /// \param tp is a set of properties to associate with the new comment (may be zero)
  /// \param fad is the address of the function to which the comment belongs
  /// \param ad is the address to which the comment is attached
  /// \param txt is the body of the comment
  /// \return \b true if a new Comment was created, \b false if there was a duplicate
  virtual bool addCommentNoDuplicate(uint4 tp,const Address &fad,const Address &ad,const string &txt)=0;

  /// \brief Remove the given Comment object from the container
  ///
  /// \param com is the given Comment
  virtual void deleteComment(Comment *com)=0;

  /// \brief Get an iterator to the beginning of comments for a single function
  ///
  /// \param fad is the address of the function
  /// \return the beginning iterator
  virtual CommentSet::const_iterator beginComment(const Address &fad) const=0;

  /// \brief Get an iterator to the ending of comments for a single function
  ///
  /// \param fad is the address of the function
  /// \return the ending iterator
  virtual CommentSet::const_iterator endComment(const Address &fad) const=0;

  /// \brief Encode all comments in the container to a stream
  ///
  /// Writes a \<commentdb> element, with \<comment> children for each Comment object.
  /// \param encoder is the stream encoder
  virtual void encode(Encoder &encoder) const=0;

  /// \brief Decode all comments from a \<commentdb> element
  ///
  /// \param decoder is the stream decoder
  virtual void decode(Decoder &decoder)=0;
};


/// \brief An in-memory implementation of the CommentDatabase API
///
/// All Comment objects are held in memory in a sorted container.  This
/// can be used as stand-alone database of comments, or it can act as a
/// cache for some other container.
class CommentDatabaseInternal : public CommentDatabase {
  CommentSet commentset;			///< The sorted set of Comment objects
public:
  CommentDatabaseInternal(void);		///< Constructor
  virtual ~CommentDatabaseInternal(void);
  virtual void clear(void);
  virtual void clearType(const Address &fad,uint4 tp);
  virtual void addComment(uint4 tp,const Address &fad,
			  const Address &ad,const string &txt);
  virtual bool addCommentNoDuplicate(uint4 tp,const Address &fad,const Address &ad,const string &txt);
  virtual void deleteComment(Comment *com);
  virtual CommentSet::const_iterator beginComment(const Address &fad) const;
  virtual CommentSet::const_iterator endComment(const Address &fad) const;
  virtual void encode(Encoder &encoder) const;
  virtual void decode(Decoder &decoder);
};

/// \brief A class for sorting comments into and within basic blocks
///
/// The decompiler endeavors to display comments within the flow of the
/// source code statements it generates. Comments should be placed at or near
/// the statement that encompasses the address of the original instruction
/// to which the comment is attached. This is complicated by the fact that
/// instructions may get removed and transformed during decompilation and even whole
/// basic blocks may get removed.
///
/// This class sorts comments into the basic block that contains
/// it. As statements are emitted, comments can get picked up, in the correct order,
/// even if there is no longer a specific p-code operation at the comment's address.
/// The decompiler maintains information about basic blocks that have been entirely
/// removed, in which case, the user can elect to not display the corresponding comments.
///
/// This class also acts as state for walking comments within a specific basic block or
/// within the header.
class CommentSorter {
public:
  enum {
    header_basic = 0,		///< Basic header comments
    header_unplaced = 1		///< Comment that can't be placed in code flow
  };
private:
  /// \brief The sorting key for placing a Comment within a specific basic block
  struct Subsort {
    int4 index;			///< Either the basic block index or -1 for a function header
    uint4 order;		///< The order index within the basic block
    uint4 pos;			///< A final count to guarantee a unique sorting

    /// \brief Compare comments based on basic block, then position within the block
    ///
    /// \param op2 is the other key to compare with \b this
    /// \return \b true if \b this gets ordered before the other key
    bool operator<(const Subsort &op2) const {
      if (index == op2.index) {
	if (order == op2.order)
	  return (pos < op2.pos);
	return (order < op2.order);
      }
      return (index < op2.index);
    }

    /// \brief Initialize a key for a header comment
    ///
    /// \param headerType can be either \b header_basic or \b header_unplaced
    void setHeader(uint4 headerType) {
      index = -1;		// -1 indicates a header comment
      order = headerType;
    }

    /// \brief Initialize a key for a basic block position
    ///
    /// \param i is the index of the basic block
    /// \param ord is the position within the block
    void setBlock(int4 i,uint4 ord) {
      index = i;
      order = ord;
    }
  };
  map<Subsort,Comment *> commmap;			///< Comments for the current function, sorted by block
  mutable map<Subsort,Comment *>::const_iterator start;	///< Iterator to current comment being walked
  map<Subsort,Comment *>::const_iterator stop;		///< Last comment in current set being walked
  map<Subsort,Comment *>::const_iterator opstop;	///< Statement landmark within current set of comments
  bool displayUnplacedComments;				///< True if unplaced comments should be displayed (in the header)
  bool findPosition(Subsort &subsort,Comment *comm,const Funcdata *fd);	///< Establish sorting key for a Comment
public:
  CommentSorter(void) { displayUnplacedComments = false; }	///< Constructor
  void setupFunctionList(uint4 tp,const Funcdata *fd,const CommentDatabase &db,bool displayUnplaced);
  void setupBlockList(const FlowBlock *bl);		///< Prepare to walk comments from a single basic block
  void setupOpList(const PcodeOp *op);			///< Establish a p-code landmark within the current set of comments
  void setupHeader(uint4 headerType);			///< Prepare to walk comments in the header
  bool hasNext(void) const { return (start!=opstop); }	///< Return \b true if there are more comments to emit in the current set
  Comment *getNext(void) const { Comment *res=(*start).second; ++start; return res; }	///< Advance to the next comment
};

} // End namespace ghidra
#endif
