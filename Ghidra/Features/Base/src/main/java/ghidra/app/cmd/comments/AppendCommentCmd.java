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
package ghidra.app.cmd.comments;

import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 *  Command to append a specific type of comment on a code unit.
 */
public class AppendCommentCmd implements Command<Program> {

	private Address address;
	private CommentType commentType;
	private String comment;
	private String separator;
	private String message;

	/**
	 * Construct command
	 * @param addr address of code unit where comment will be placed
	 * @param commentType valid comment type (see {@link CodeUnit#EOL_COMMENT}, 
	 * {@link CodeUnit#PLATE_COMMENT}, etc)
	 * @param comment comment for code unit, should not be null
	 * @param separator characters to separate the new comment from the previous comment when
	 * concatenating.
	 */
	@Deprecated(forRemoval = true, since = "11.4")
	public AppendCommentCmd(Address addr, int commentType, String comment, String separator) {
		this(addr, CommentType.valueOf(commentType), comment, separator);
	}

	/**
	 * Construct command
	 * @param addr address of code unit where comment will be placed
	 * @param commentType comment type
	 * @param comment comment for code unit, should not be null
	 * @param separator characters to separate the new comment from the previous comment when
	 * concatenating.
	 */
	public AppendCommentCmd(Address addr, CommentType commentType, String comment,
			String separator) {
		this.address = addr;
		this.commentType = commentType;
		this.comment = comment;
		this.separator = separator;
	}

	@Override
	public String getName() {
		return "Append Comment";
	}

	@Override
	public boolean applyTo(Program program) {
		CodeUnit cu = getCodeUnit(program);
		if (cu == null) {
			message = "No Instruction or Data found for address " + address.toString() +
				"  Is this address valid?";
			return false;
		}
		String previousComment = cu.getComment(commentType);
		String newComment =
			(previousComment != null) ? previousComment + separator + comment : comment;
		cu.setComment(commentType, newComment);
		return true;
	}

	/**
	 * Get the code unit from the program location provider.
	 *
	 * @return CodeUnit null if there is no location provider.
	 */
	private CodeUnit getCodeUnit(Program program) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu == null) {
			return null;
		}
		Address cuAddr = cu.getMinAddress();
		if (cu instanceof Data && !address.equals(cuAddr)) {
			Data data = (Data) cu;
			return data.getPrimitiveAt((int) address.subtract(cuAddr));
		}
		return cu;
	}

	@Override
	public String getStatusMsg() {
		return message;
	}

}
