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

import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

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
	private String msg;

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

	/**
	 * The name of the edit action.
	 */
	@Override
	public String getName() {
		return "Set Comments";
	}

	/**
	 * return true if the newValue and oldValue are different
	 * @param newValue the value that we desire to set
	 * @param oldValue the existing value
	 * @return boolean
	 */
	private boolean commentChanged(String newValue, String oldValue) {
		if (newValue == null && oldValue == null) {
			return false;
		}
		if (newValue != null) {
			return !newValue.equals(oldValue);
		}
		return !oldValue.equals(newValue);
	}

	@Override
	public boolean applyTo(Program program) {
		CodeUnit cu = getCodeUnit(program);

		if (cu != null) {
			if (commentChanged(cu.getComment(CommentType.PRE), preComment)) {
				String updatedPreComment = CommentUtils.fixupAnnotations(preComment, program);
				updatedPreComment = CommentUtils.sanitize(updatedPreComment);
				cu.setComment(CommentType.PRE, updatedPreComment);
			}
			if (commentChanged(cu.getComment(CommentType.POST), postComment)) {
				String updatedPostComment = CommentUtils.fixupAnnotations(postComment, program);
				updatedPostComment = CommentUtils.sanitize(updatedPostComment);
				cu.setComment(CommentType.POST, updatedPostComment);
			}
			if (commentChanged(cu.getComment(CommentType.EOL), eolComment)) {
				String updatedEOLComment = CommentUtils.fixupAnnotations(eolComment, program);
				updatedEOLComment = CommentUtils.sanitize(updatedEOLComment);
				cu.setComment(CommentType.EOL, updatedEOLComment);
			}
			if (commentChanged(cu.getComment(CommentType.PLATE), plateComment)) {
				String updatedPlateComment = CommentUtils.fixupAnnotations(plateComment, program);
				updatedPlateComment = CommentUtils.sanitize(updatedPlateComment);
				cu.setComment(CommentType.PLATE, updatedPlateComment);
			}
			if (commentChanged(cu.getComment(CommentType.REPEATABLE), repeatableComment)) {
				String updatedRepeatableComment =
					CommentUtils.fixupAnnotations(repeatableComment, program);
				updatedRepeatableComment = CommentUtils.sanitize(updatedRepeatableComment);
				cu.setComment(CommentType.REPEATABLE, updatedRepeatableComment);
			}
		}
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
		return msg;
	}

}
