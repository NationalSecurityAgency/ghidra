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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.SeparatedCodeFromCompilerSupportMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link SeparatedCodeFromCompilerSupportMsSymbol} symbol. 
 */
// TODO: Need to evaluate relationship to function symbols.
// TODO: Need to create anonymous name for this as a function?
public class SeparatedCodeSymbolApplier extends MsSymbolApplier {

	private SeparatedCodeFromCompilerSupportMsSymbol symbol;

	private String craftedName;

	private Address specifiedAddress;
	private BlockCommentsManager comments;

	private int symbolBlockNestingLevel;
	private Address currentBlockAddress;

	private List<MsSymbolApplier> allAppliers = new ArrayList<>();

	private static AbstractMsSymbolIterator validateSymbol(AbstractMsSymbolIterator iter) {
		if (!(iter.peek() instanceof SeparatedCodeFromCompilerSupportMsSymbol)) {
			throw new IllegalArgumentException("Not a SeparatedCodeFromCompilerSupportMsSymbol");
		}
		return iter;
	}

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 * @throws CancelledException upon user cancellation
	 */
	public SeparatedCodeSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter)
			throws CancelledException {
		super(applicator, validateSymbol(iter));

		symbol = (SeparatedCodeFromCompilerSupportMsSymbol) iter.next();

		specifiedAddress = applicator.getAddress(symbol);

		// Make up name.  TODO: decide if need better anonymous name
		craftedName = String.format("CompilerSeparatedCode%s", specifiedAddress);

		symbolBlockNestingLevel = 0;

		comments = new BlockCommentsManager();
		currentBlockAddress = null;

		manageBlockNesting(this);

		while (notDone()) {
			applicator.checkCanceled();
			MsSymbolApplier applier = applicator.getSymbolApplier(iter);
			if (!(applier instanceof EndSymbolApplier)) {
				Msg.info(this, "Unexpected applier in " + getClass().getSimpleName() + ": " +
					applier.getClass().getSimpleName());
			}
			allAppliers.add(applier);
			applier.manageBlockNesting(this);
		}
	}

	@Override
	void manageBlockNesting(MsSymbolApplier applierParam) {
		beginBlock(specifiedAddress);
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		// Do nothing.
	}

	@Override
	void apply() throws PdbException, CancelledException {
		if (applicator.isInvalidAddress(currentBlockAddress, craftedName)) {
			return;
		}
		// DO NOTHING FOR NOW.  TODO: should we have a configuration option?
		//  Note: these comments can be noise in the decompiler an code browser
		setComments(false);
	}

	private void setComments(boolean enabled) {
		if (enabled) {
			String existingComment = applicator.getProgram().getListing().getComment(
				CodeUnit.PRE_COMMENT, specifiedAddress);
			String p = "*************************************************************\n";
			String newComment =
				String.format(p + "* Separated code (from the compiler): %s - %s *\n" + p,
					specifiedAddress.toString(),
					specifiedAddress.add(symbol.getBlockLength() - 1).toString());
			String comment =
				(existingComment == null) ? newComment : existingComment + "\n" + newComment;
			SetCommentCmd.createComment(applicator.getProgram(), specifiedAddress, comment,
				CodeUnit.PRE_COMMENT);
		}
	}

	private boolean notDone() {
		return (symbolBlockNestingLevel > 0) && iter.hasNext();
	}

	void endBlock() {
		if (--symbolBlockNestingLevel < 0) {
			applicator.appendLogMsg("Block Nesting went negative at " + specifiedAddress);
		}
	}

	void beginBlock(Address startAddress) {
		currentBlockAddress = startAddress;
		++symbolBlockNestingLevel;
	}

}
