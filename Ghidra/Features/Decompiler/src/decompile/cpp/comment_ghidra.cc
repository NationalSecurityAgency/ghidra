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
#include "comment_ghidra.hh"

CommentDatabaseGhidra::CommentDatabaseGhidra(ArchitectureGhidra *g)
  : CommentDatabase()
{
  ghidra = g;
  cachefilled = false;
}

/// Fetch all comments for the function in one chunk. Deserialize them and
/// store the Comment objects in the cache
/// \param fad is the address of the given function
void CommentDatabaseGhidra::fillCache(const Address &fad) const

{
  Document *doc;
  uint4 commentfilter;

  if (cachefilled) return;	// Already queried ghidra
  cachefilled = true;
  // Gather which types of comments are being printed currently
  commentfilter = ghidra->print->getHeaderComment();
  commentfilter |= ghidra->print->getInstructionComment();
  if (commentfilter==0) return;
  CommentSet::const_iterator iter,iterend;
  iter = cache.beginComment(fad);
  iterend = cache.endComment(fad);

  doc = ghidra->getComments(fad,commentfilter);
  if (doc != (Document *)0) {
    cache.restoreXml(doc->getRoot(),ghidra);
    delete doc;
  }
}

/// For the Ghidra implementation of CommentDatabase, addComment() is currently only
/// called by the warning routines which generates the
/// \e warning and \e warningheader comment types. Neither of
/// these types is intended to be a permanent comment in the
/// database, so we only add the comment to the cache
void CommentDatabaseGhidra::addComment(uint4 tp,
				       const Address &fad,
				       const Address &ad,
				       const string &txt)
{
  cache.addComment(tp,fad,ad,txt);
}

bool CommentDatabaseGhidra::addCommentNoDuplicate(uint4 tp,const Address &fad,const Address &ad,
						  const string &txt)
{
  return cache.addCommentNoDuplicate(tp,fad,ad,txt);
}

CommentSet::const_iterator CommentDatabaseGhidra::beginComment(const Address &fad) const

{
  fillCache(fad);
  return cache.beginComment(fad);
}

CommentSet::const_iterator CommentDatabaseGhidra::endComment(const Address &fad) const

{
  return cache.endComment(fad);
}

