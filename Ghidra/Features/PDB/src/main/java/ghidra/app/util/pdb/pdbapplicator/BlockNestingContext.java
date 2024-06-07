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
package ghidra.app.util.pdb.pdbapplicator;

import ghidra.program.model.address.Address;

/**
 * Manages block nesting for function-related symbols
 */
public class BlockNestingContext {

	private static final String BLOCK_INDENT = "   ";

	private DefaultPdbApplicator applicator;
	private BlockCommentsManager comments;
	private int nestingLevel;
	private Address currentBlockAddress;

	public BlockNestingContext(DefaultPdbApplicator applicator) {
		this.applicator = applicator;
		nestingLevel = 0;
		comments = new BlockCommentsManager();
	}

	public boolean notDone() {
		return nestingLevel > 0;
	}

	public Address getCurrentBlockAddress() {
		return currentBlockAddress;
	}

	public BlockCommentsManager getComments() {
		return comments;
	}

	public int endBlock() {
		if (--nestingLevel < 0) {
			applicator.appendLogMsg("Block Nesting went negative for ending block that began at " +
				currentBlockAddress);
		}
		if (nestingLevel == 0) {
			//currentFunctionSymbolApplier = null;
		}
		return nestingLevel;
	}

	public int getLevel() {
		return nestingLevel;
	}

	public void beginBlock(Address startAddress, String name, long length) {
		++nestingLevel;
		currentBlockAddress = startAddress;
		if (!applicator.getPdbApplicatorOptions().applyCodeScopeBlockComments()) {
			return;
		}
		if (applicator.isInvalidAddress(startAddress, name)) {
			return;
		}
		String indent = getIndent(nestingLevel);
		String baseComment = "level " + nestingLevel + ", length " + length;
		String preComment = indent + "PDB: Block Beg, " + baseComment;
		if (name != null && !name.isEmpty()) {
			preComment += " (" + name + ")";
		}
		comments.addPreComment(startAddress, preComment);

		String postComment = indent + "PDB: Block End, " + baseComment;
		Address endAddress = startAddress.add(((length <= 0) ? 0 : length - 1));
		comments.addPostComment(endAddress, postComment);
	}

	public String getIndent(int indentLevel) {
		return BLOCK_INDENT.repeat(indentLevel);
	}

}
