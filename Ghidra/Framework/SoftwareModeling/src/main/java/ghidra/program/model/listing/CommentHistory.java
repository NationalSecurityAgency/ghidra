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
package ghidra.program.model.listing;

import java.util.Date;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.address.Address;

/**
 * Container class for information about changes to a comment.
 */
public class CommentHistory {

	private Address addr;
	private int commentType;
	private Date modificationDate;
	private String userName;
	private String comments;

	/**
	 * Constructs a new CommentHistory object
	 * @param addr the address of the comment
	 * @param commentType the type of comment
	 * @param userName the name of the user that changed the comment
	 * @param comments the list of comments.
	 * @param modificationDate the date the comment was changed.
	 */
	public CommentHistory(Address addr, int commentType, String userName, String comments,
			Date modificationDate) {
		this.addr = addr;
		this.commentType = commentType;
		this.userName = userName;
		this.comments = comments;
		this.modificationDate = modificationDate;
	}

	/**
	 * Get address for this label history object
	 * @return address for this label history object.
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * Get the user that made the change
	 * @return the user that made the change
	 */
	public String getUserName() {
		return userName;
	}

	/**
	 * Get the comments for this history object
	 * @return the comments for this history object
	 */
	public String getComments() {
		return comments;
	}

	/**
	 * Get the comment type
	 * @return the comment type
	 */
	public int getCommentType() {
		return commentType;
	}

	/**
	 * Get the modification date
	 * @return the modification date
	 */
	public Date getModificationDate() {
		return modificationDate;
	}

	@Override
	public String toString() {

		//@formatter:off
		return "{\n" +
			"\tuser: " + userName + ",\n" +
			"\tdate: " + modificationDate + ",\n" + 
			"\taddress: " + addr + ",\n" +
			"\tcomment: " + StringUtils.abbreviate(comments, 10) + "\n" +
		"}";		
		//@formatter:on
	}
}
