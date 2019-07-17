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
/// \file comment_ghidra.hh
/// \brief Obtain comments by talking to a Ghidra client
#ifndef __COMMENT_GHIDRA__
#define __COMMENT_GHIDRA__

#include "comment.hh"
#include "ghidra_arch.hh"

/// \brief An implementation of CommentDatabase backed by a Ghidra client
///
/// Comment information about particular functions is obtained by querying
/// a Ghidra client. All comments for a single function are queried at once, and
/// results are cached in this object. The cache needs to be cleared between
/// functions using the clear() method.
class CommentDatabaseGhidra : public CommentDatabase {
  ArchitectureGhidra *ghidra;			///< The Architecture and connection to the Ghidra client
  mutable CommentDatabaseInternal cache;	///< A cache of Comment objects received from the Ghidra client
  mutable bool cachefilled;			///< Set to \b true if comments for the current function have been fetched
  void fillCache(const Address &fad) const;	///< Fetch comments for the given function
public:
  CommentDatabaseGhidra(ArchitectureGhidra *g);	///< Constructor
  virtual void clear(void) { cache.clear(); cachefilled=false; }
  virtual void clearType(const Address &fad,uint4 tp) {
    cache.clearType(fad,tp);
  }
  virtual void addComment(uint4 tp,const Address &fad,
			  const Address &ad,const string &txt);
  virtual bool addCommentNoDuplicate(uint4 tp,const Address &fad,const Address &ad,const string &txt);
  virtual void deleteComment(Comment *com) {
    throw LowlevelError("deleteComment unimplemented"); }
  virtual CommentSet::const_iterator beginComment(const Address &fad) const;
  virtual CommentSet::const_iterator endComment(const Address &fad) const;
  virtual void saveXml(ostream &s) const {
    throw LowlevelError("commentdb::saveXml unimplemented"); }
  virtual void restoreXml(const Element *el,const AddrSpaceManager *trans) {
    throw LowlevelError("commentdb::restoreXml unimplemented"); }
};

#endif
