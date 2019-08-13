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
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 *  Command to set a specific type of comment on a code unit.
 */
public class SetCommentCmd implements Command {

	private Address address;
	private int commentType;
	private String comment;
	private String cmdName;
	private String message;

	/**
	 * Construct command
	 * @param addr address of code unit where comment will be placed
	 * @param commentType valid comment type (see CodeUnit)
	 * @param comment comment for code unit
	 */
	public SetCommentCmd(Address addr, int commentType, String comment) {
		this.address = addr;
		this.commentType = commentType;
		this.comment = comment;
		cmdName = comment == null ? "Delete Comment" : "Set Comment";
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return cmdName;
	}

	/**
	 * return true if the newValue and oldValue are different
	 * @param newValue a String containing the new comment
	 * @param oldValue a String containing the old comment
	 * @return true if newValue and oldValue are different.
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

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		CodeUnit cu = getCodeUnit((Program) obj);
		if (cu == null) {
			message = "No Instruction or Data found for address " + address.toString() +
				"  Is this address valid?";
			return false;
		}
		if (commentChanged(cu.getComment(commentType), comment)) {
			cu.setComment(commentType, comment);
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

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return message;
	}

	/**
	 * Creates the specified comment of the specified type at address.  The current comment of
	 * this commentType will be cleared.
	 * 
	 * @param program the program being analyzed
	 * @param addr the address where data is created
	 * @param comment the comment about the data
	 * @param commentType the type of comment ({@link CodeUnit#PLATE_COMMENT}, 
	 * {@link CodeUnit#PRE_COMMENT}, {@link CodeUnit#EOL_COMMENT}, {@link CodeUnit#POST_COMMENT},
	 * {@link CodeUnit#REPEATABLE_COMMENT}) 
	 */
	public static void createComment(Program program, Address addr, String comment,
			int commentType) {
		SetCommentCmd commentCmd = new SetCommentCmd(addr, commentType, comment);
		commentCmd.applyTo(program);
	}

}
