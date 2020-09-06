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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

/**
 * Manages the nesting of scoping blocks for functions and scoped variables.
 */
public class BlockCommentsManager {

	private static final String BLOCK_INDENT = "   ";

//	private int symbolBlockNestingLevel;
	private Map<Address, String> blockPreComments;
	private Map<Address, String> blockPostComments;

	BlockCommentsManager() {
//		symbolBlockNestingLevel = 0;
		blockPreComments = new HashMap<>();
		blockPostComments = new HashMap<>();
	}

	void applyTo(Program program) {
		applyTo(program, 0L);
	}

	void applyTo(Program program, long addressDelta) {
		finalizeBlockComments(program, addressDelta);
	}

//	int beginBlock(Address startAddress, String name, long length) {
//		++symbolBlockNestingLevel;
//		addBlockComment(startAddress, name, length, symbolBlockNestingLevel);
//		return symbolBlockNestingLevel;
//	}
//
//	int endBlock() throws PdbException {
//		if (--symbolBlockNestingLevel < 0) {
//			// TODO: eliminate exception and handle another way.
//			throw new PdbException("Block Nesting went negative");
//		}
//		if (symbolBlockNestingLevel == 0) {
//			//currentFunctionSymbolApplier = null;
//		}
//		return symbolBlockNestingLevel;
//	}
//
//	int getBlockNestingLevel() {
//		return symbolBlockNestingLevel;
//	}
//
	void addPreComment(Address address, String preComment) {
		String existingPreComment = blockPreComments.get(address);
		preComment =
			(existingPreComment == null) ? preComment : existingPreComment + "\n" + preComment;
		blockPreComments.put(address, preComment);
	}

	void addPostComment(Address address, String postComment) {
		String existingPostComment = blockPostComments.get(address);
		postComment =
			(existingPostComment == null) ? postComment : postComment + "\n" + existingPostComment;
		blockPostComments.put(address, postComment);
	}

	void addBlockComment(Address startAddress, String name, long length, int nestingLevel) {
		String indent = "";
		for (int i = 1; i < nestingLevel; i++) {
			indent += BLOCK_INDENT;
		}

		String baseComment = "level " + nestingLevel + ", length " + length;
		String preComment = indent + "PDB: Block Beg, " + baseComment;
		if (!name.isEmpty()) {
			preComment += " (" + name + ")";
		}
		String postComment = indent + "PDB: Block End, " + baseComment;

		addPreComment(startAddress, preComment);
//		String existingPreComment = blockPreComments.get(startAddress);
//		preComment =
//			(existingPreComment == null) ? preComment : existingPreComment + "\n" + preComment;
//		blockPreComments.put(startAddress, preComment);

		Address endAddress = startAddress.add(((length <= 0) ? 0 : length - 1));
		addPostComment(endAddress, postComment);
//		Address endCodeUnitAddress =
//			program.getListing().getCodeUnitContaining(endAddress).getAddress();
//
//		processPostComment(endCodeUnitAddress, postComment);
//		String existingPostComment = blockPostComments.get(endCodeUnitAddress);
//		postComment =
//			(existingPostComment == null) ? postComment : postComment + "\n" + existingPostComment;
//		blockPostComments.put(endCodeUnitAddress, postComment);
	}

	private void finalizeBlockComments(Program program, long addressDelta) {
		for (Map.Entry<Address, String> entry : blockPreComments.entrySet()) {
			appendBlockComment(program, entry.getKey().add(addressDelta), entry.getValue(),
				CodeUnit.PRE_COMMENT);
		}
		for (Map.Entry<Address, String> entry : blockPostComments.entrySet()) {
			Address endCodeUnitAddress = program.getListing().getCodeUnitContaining(
				entry.getKey().add(addressDelta)).getAddress();
			appendBlockComment(program, endCodeUnitAddress, entry.getValue(),
				CodeUnit.POST_COMMENT);
		}
	}

	private void appendBlockComment(Program program, Address address, String text,
			int commentType) {
		String comment = program.getListing().getComment(commentType, address);
		comment = (comment == null) ? text : comment + "\n" + text;
		SetCommentCmd.createComment(program, address, comment, commentType);
	}

}
