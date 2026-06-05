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
package ghidra.features.base.replace.items;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.exception.AssertException;

/**
 * QuickFix for updating listing comments.
 */
public class UpdateCommentQuickFix extends QuickFix {

	private Address address;
	private CommentType type;

	/**
	 * Constructor
	 * @param program the program containing the comment to be renamed
	 * @param address The address where the comment is located
	 * @param type the type of comment (Pre, Post, EOL, etc.)
	 * @param comment the original comment text
	 * @param newComment  the new comment text
	 */
	public UpdateCommentQuickFix(Program program, Address address, CommentType type, String comment,
			String newComment) {

		super(program, comment, newComment);
		this.address = address;
		this.type = type;
	}

	@Override
	public String getActionName() {
		return "Update";
	}

	@Override
	public String getItemType() {
		return "Code Comment";
	}

	@Override
	public String doGetCurrent() {
		return program.getListing().getComment(type, address);
	}

	@Override
	public void execute() {
		program.getListing().setComment(address, type, replacement);
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public ProgramLocation getProgramLocation() {
		switch (type) {
			case EOL:
				return new EolCommentFieldLocation(program, address, null, null, 0, 0, 0);
			case PLATE:
				return new PlateFieldLocation(program, address, null, 0, 0, null, 0);
			case POST:
				return new PostCommentFieldLocation(program, address, null, null, 0, 0);
			case PRE:
				return new CommentFieldLocation(program, address, null, null, type, 0, 0);
			case REPEATABLE:
				return new RepeatableCommentFieldLocation(program, address, null, null, 0, 0, 0);
			default:
				throw new AssertException("Unsupported comment type: " + type.name());
		}
	}

	@Override
	public String getPath() {
		return null;
	}

}
