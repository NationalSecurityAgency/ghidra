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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;

/**
 * Change record for comment changes
 */
public class CommentChangeRecord extends ProgramChangeRecord {

	// types defined in CodeUnit
	private int commentType;

	/**
	 * Constructor
	 * @param commentType the type of comment (as defined in {@link CodeUnit})
	 * @param address the address of the comment change
	 * @param oldValue the old comment (may be null for a new comment)
	 * @param newValue the new comment (may be null if the comment was deleted)
	 */
	public CommentChangeRecord(int commentType, Address address, String oldValue, String newValue) {
		super(ProgramEvent.COMMENT_CHANGED, address, address, null, oldValue, newValue);
		this.commentType = commentType;
	}

	/**
	 * Returns the comment type as defined in {@link CodeUnit}.
	 * @return the comment type
	 */
	public int getCommentType() {
		return commentType;
	}

	/**
	 * Returns the previous comment or null if there was no previous comment.
	 * @return the previous comment or null if there was no previous comment.
	 */
	public String getOldComment() {
		return (String) getOldValue();
	}

	/**
	 * Returns the new comment or null if this is a result of deleting the comment.
	 * @return the new comment or null if this is a result of deleting the comment
	 */
	public String getNewComment() {
		return (String) getNewValue();
	}

}
