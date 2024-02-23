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
// This script looks for offcut instruction(s) in the current selection or location and
// automatically fixes "safe" offcuts. This script is suitable for correcting polyglot instruction
// executable size optimizations, LOCK prefix issues, and offcut code used for code obfuscation.
// 
// Offcuts are determined to be safe if they don't have additional conflicting offcuts in the same
// base instruction.
// The new instruction length override will be set by assuming there actually is an instruction at
// the safe offcut reference. If a failure to flow this instruction occurs the script will emit
// a warning about the exception and continue processing.
// A check is done for pseudo-disassembly viability before setting the instruction or flowing
// the code so these exceptions shouldn't be reached.
//
// When fixups are applied any existing Error level bookmarks for the Bad Instruction will be
// removed and replaced with info that an offcut was fixed. These can be interpreted that
// assumptions were made about the context flowed locally to the fixed instruction that should be
// taken as fact cautiously since the binary is already confirmed to be well behaved, that is
// strictly flowed.
//
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.script.ScriptMessage;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;

public class FixOffcutInstructionScript extends GhidraScript {

	public final String INFO_BOOKMARK_CATEGORY = "Offcut Instruction";
	public final String INFO_BOOKMARK_COMMENT = "Fixed offcut instruction";
	public final int MAX_OFFCUT_DISTANCE = 64;
	private Listing currentListing;
	private BookmarkManager currentBookmarkManager;
	private ReferenceManager currentReferenceManager;
	private int alignment;

	@Override
	protected void run() throws Exception {
		currentListing = currentProgram.getListing();
		currentBookmarkManager = currentProgram.getBookmarkManager();
		currentReferenceManager = currentProgram.getReferenceManager();
		alignment = currentProgram.getLanguage().getInstructionAlignment();
		// run in strict mode if a selection
		final boolean doExtraValidation = currentSelection != null;

		// restrict processing to the current selection
		final AddressSet restrictedSet =
			(currentSelection != null) ? (new AddressSet(currentSelection))
					: (new AddressSet(currentLocation.getAddress()));

		final InstructionIterator instrIter = currentListing.getInstructions(restrictedSet, true);

		while (instrIter.hasNext() && !monitor.isCancelled()) {
			final Instruction curInstr = instrIter.next();

			if (curInstr.isLengthOverridden()) {
				continue;
			}

			final Address offcutAddress = getQualifiedOffcutAddress(curInstr, doExtraValidation);
			if (offcutAddress == null) {
				continue;
			}

			// This script is only useful for static offcut instruction fixing. Dynamic offcuts
			// will raise an exception that will be logged here.
			try {
				fixOffcutInstruction(curInstr, offcutAddress);
			}
			catch (Exception e) {
				Msg.error(this, new ScriptMessage("Failed to fix offuct instruction at " +
					curInstr.getAddressString(false, true)), e);
			}
		}
	}

	private Address getQualifiedOffcutAddress(final Instruction instr,
			final boolean doExtraValidation) {
		// short-circuit too small instructions
		if (instr.getLength() < 2) {
			return null;
		}
		final Address instrAddr = instr.getAddress();
		final AddressSet instrBody =
			new AddressSet(instr.getMinAddress().add(1), instr.getMaxAddress());
		Address offcutAddress = null;
		for (final Address address : currentReferenceManager
				.getReferenceDestinationIterator(instrBody, true)) {
			if ((address.getOffset() % alignment) != 0) {
				continue;
			}
			for (final Reference reference : currentReferenceManager.getReferencesTo(address)) {
				final RefType refType = reference.getReferenceType();
				if (doExtraValidation && Math.abs(
					instrAddr.subtract(reference.getFromAddress())) > MAX_OFFCUT_DISTANCE) {
					continue;
				}
				if (refType.isJump() && refType.hasFallthrough()) {
					if (offcutAddress == null) {
						offcutAddress = address;
					}
				}
				else {
					continue;
				}
			}
		}
		return offcutAddress;
	}

	private void fixOffcutInstruction(Instruction instr, Address offcutAddress)
			throws CodeUnitInsertionException {
		if (!canDisassembleAt(instr, offcutAddress)) {
			Msg.warn(this,
				new ScriptMessage("\t> Offcut construction would not be valid. Skipping..."));
			return;
		}

		instr.setLengthOverride((int) offcutAddress.subtract(instr.getMinAddress()));

		// Once the override is complete there will be code to disassemble.
		disassemble(offcutAddress);

		// Usually there will be a bookmark complaining about how there is a well formed instruction
		// already at this location which this change has obsoleted
		fixBookmark(offcutAddress);
	}

	private void fixBookmark(Address at) {
		final Bookmark bookmark = currentBookmarkManager.getBookmark(at, BookmarkType.ERROR,
			Disassembler.ERROR_BOOKMARK_CATEGORY);
		if (bookmark != null) {
			currentBookmarkManager.removeBookmark(bookmark);

			// inform the user this instruction was fixed. even though the disassembly appears
			// fixed the fact remains that there are two potentially conflicting context flows
			// happening at this instruction and it was assumed that the exposed instruction holds
			// flow attention for execution here due to the direct references.
			// team opted for a simple remark rather repeat this fact about context since
			// this script being applied implies the user understands the potential for conflicts
			currentBookmarkManager.setBookmark(at, BookmarkType.INFO, INFO_BOOKMARK_CATEGORY,
				INFO_BOOKMARK_COMMENT);
		}
	}

	protected boolean canDisassembleAt(Instruction instr, Address at) {
		try {
			// only the instruction prototype is needed to determine if an instruction can exist
			// in the offcut location
			final PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);
			final PseudoInstruction testInstr = pdis.disassemble(at);
			return (testInstr != null && testInstr.getMaxAddress().equals(instr.getMaxAddress()));
		}
		catch (InsufficientBytesException | UnknownInstructionException
				| UnknownContextException e) {
			Msg.error(this,
				"Could not disassemble instruction at " + at + " (" + e.getMessage() + ")", e);
			return false;
		}
	}

}
