/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import docking.widgets.OptionDialog;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

public class MoveMemoryRangeContents extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (!(currentProgram instanceof ProgramDB)) {
			Msg.showError(this, null, "No Program Found", "This script requires an open program");
			return;
		}

		ProgramDB program = (ProgramDB) currentProgram;

		try {
			program.checkExclusiveAccess();
		}
		catch (Exception e) {
			Msg.showError(this, null, "Program Error",
				"This script requires an exclusive checkout on the program");
			return;
		}

		Listing listing = currentProgram.getListing();

		if (currentSelection == null || currentSelection.getNumAddressRanges() != 1) {
			Msg.showError(this, null, "Invalid Selection",
				"Action requires a single selected memory range within a single memory block");
			return;
		}

		AddressRange srcRange = currentSelection.getFirstRange();
		Address srcStart = srcRange.getMinAddress();
		int length = (int) srcRange.getMaxAddress().subtract(srcStart) + 1;
		MemoryBlock block1 = program.getMemory().getBlock(srcStart);
		MemoryBlock block2 = program.getMemory().getBlock(srcRange.getMaxAddress());
		if (block1 == null || block1 != block2 || !block1.isInitialized()) {
			Msg.showError(this, null, "Invalid Selection",
				"Action requires a single selected memory range within a single initialized memory block");
			return;
		}

		Address destStart = askAddress("Memory Destination", "Enter destination address:");

		MemoryBlock block = program.getMemory().getBlock(destStart);
		if (block == null || !block.isInitialized()) {
			Msg.showError(this, null, "Invalid Destination",
				"Initialized memory block not found at destination address: " + destStart);
			return;
		}
		long availableSpace = block.getEnd().subtract(destStart) + 1;
		if (availableSpace < length) {
			Msg.showError(this, null, "Memory Move Failed",
				"Insufficient space in specified memory block starting at " + destStart + ".\n" +
					"Selected range is 0x" + Long.toHexString(length) + " bytes long");
			return;
		}
		Address destEnd = destStart.add(length - 1);

		int resp =
			OptionDialog.showOptionDialog(null, "Confirm Memory Move",
				"Do you wish to overwrite all bytes, code units, symbols and references from\n" +
					"the specified destination range: " + destStart + " to " + destEnd, "Continue");
		if (resp != OptionDialog.OPTION_ONE) {
			return;
		}

		monitor.setMessage("Clearing old code units...");
		listing.clearCodeUnits(destStart, destEnd, true, monitor);

		monitor.setMessage("Clearing old code properties...");
		listing.clearProperties(destStart, destEnd, monitor);

		monitor.setMessage("Clearing old symbols...");
		SymbolIterator symIter = program.getSymbolTable().getSymbolIterator(destStart, true);
		while (symIter.hasNext()) {
			monitor.checkCanceled();
			Symbol sym = symIter.next();
			if (sym.getAddress().compareTo(destEnd) > 0) {
				break;
			}
		}

		monitor.setMessage("Clearing old references...");
		ReferenceManager refMgr = program.getReferenceManager();
		refMgr.removeAllReferencesFrom(destStart, destEnd);

		// Remove range from all tree modules
		program.getTreeManager().deleteAddressRange(destStart, destEnd, monitor);

		monitor.setMessage("Move memory bytes...");
		byte[] bytes = new byte[4096];
		int len = length;
		Address srcAddr = srcStart;
		Address destAddr = destStart;
		while (true) {
			monitor.checkCanceled();
			int cnt = program.getMemory().getBytes(srcAddr, bytes, 0, Math.min(len, bytes.length));
			currentProgram.getMemory().setBytes(destAddr, bytes, 0, cnt);
			len -= cnt;
			if (len <= 0) {
				break;
			}
			srcAddr = srcAddr.add(cnt);
			destAddr = destAddr.add(cnt);
		}

		monitor.setMessage("Moving everything else...");
		program.moveAddressRange(srcStart, destStart, length, monitor);

		// Add tree module for old range
		program.getTreeManager().addMemoryBlock("Obsolete", srcRange);

		program.invalidate();

	}

}
