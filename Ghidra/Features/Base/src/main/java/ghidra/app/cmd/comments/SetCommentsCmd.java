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

import java.util.Objects;

import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.exception.AssertException;

/**
 * Command for editing and removing comments at an address.
 */
public class SetCommentsCmd implements Command<Program> {

	private Address address;
	private String preComment;
	private String postComment;
	private String eolComment;
	private String plateComment;
	private String repeatableComment;

	/**
	 * Construct command for setting all the different types of comments at an
	 * address.
	 * @param addr address of code unit where comment will edited
	 * @param newPreComment new pre comment
	 * @param newPostComment new post comment
	 * @param newEolComment new eol comment
	 * @param newPlateComment new plate comment
	 * @param newRepeatableComment new repeatable comment
	 */
	public SetCommentsCmd(Address addr, String newPreComment, String newPostComment,
			String newEolComment, String newPlateComment, String newRepeatableComment) {
		this.address = addr;

		this.preComment = newPreComment;
		this.postComment = newPostComment;
		this.eolComment = newEolComment;
		this.plateComment = newPlateComment;
		this.repeatableComment = newRepeatableComment;
	}

	@Override
	public String getName() {
		return "Set Comments";
	}

	@Override
	public boolean applyTo(Program program) {
		CodeUnit cu = getCodeUnit(program);
		if (cu == null) {
			return false;
		}

		Address addr = cu.getAddress();
		for (CommentType type : CommentType.values()) {
			String newComment = getComment(type);
			String oldComment = cu.getComment(type);
			if (Objects.equals(oldComment, newComment)) {
				continue;
			}

			String fixedComment = CommentUtils.fixupAnnotations(newComment, program, addr);
			fixedComment = CommentUtils.sanitize(fixedComment);
			cu.setComment(type, fixedComment);
		}
		return true;
	}

	private String getComment(CommentType type) {
		switch (type) {
			case EOL:
				return eolComment;
			case PLATE:
				return plateComment;
			case POST:
				return postComment;
			case PRE:
				return preComment;
			case REPEATABLE:
				return repeatableComment;
			default:
				throw new AssertException("Unhandled CommentType");
		}
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
		return null;
	}
}
