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
//This script cleans up the disassembly for kext files by locating "Bad Instruction" bookmarks caused by incorrectly defined data in valid code flows.
//@author 
//@category iOS
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;

public class BadInstructionCleanup extends GhidraScript {

	@Override
	public void run() throws Exception {
		BookmarkManager bmgr = currentProgram.getBookmarkManager();
		AddressSetView baddrs = bmgr.getBookmarkAddresses("Error");
		AddressSetView previousSet = baddrs;
		boolean isMoreBad = true;
		while (isMoreBad) {
			AddressIterator bai = baddrs.getAddresses(true);
			while (bai.hasNext()) {
				Address ba = bai.next();
				cleanup(ba);
			}
			while (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
				Thread.sleep(500);
			}
			baddrs = bmgr.getBookmarkAddresses("Error");
			if (baddrs.equals(previousSet)) {
				isMoreBad = false;
			}
			else {
				previousSet = baddrs;
			}
		}
	}

public void cleanup(Address ba) throws Exception {

		Program p = currentProgram;
		BookmarkManager bmgr = p.getBookmarkManager();
		Bookmark bm = bmgr.getBookmark(ba, "Error", "Bad Instruction");
		Listing listing = p.getListing();
		if (bm != null) {
			Register contextReg = p.getProgramContext().getRegister("TMode");
			Address ba_end = ba;
			if (listing.getCodeUnitAt(ba) != null) {
				ba_end = listing.getCodeUnitAt(ba).getMaxAddress();
			}
			while (getDataContaining(ba_end.add(4)) != null) {
				ba_end = getDataContaining(ba_end.add(4)).getMaxAddress();
			}
			while (getDataContaining(ba.subtract(1)) != null) {
				ba = getDataContaining(ba.subtract(1)).getAddress();
			}
			listing.clearCodeUnits(ba, ba_end, false);
			if (contextReg != null) {
				Address paddr = listing.getInstructionBefore(ba).getAddress();
				RegisterValue rv;
				if (paddr != null) {
					rv = p.getProgramContext().getRegisterValue(contextReg,
							paddr);
					p.getProgramContext().setRegisterValue(ba, ba_end, rv);
				}
			}
			DisassembleCommand cmd = new DisassembleCommand(ba, null, true);
			cmd.applyTo(p, monitor);
			Function f = getFunctionBefore(ba);
			if (f != null) {
				CreateFunctionCmd cf = new CreateFunctionCmd(f.getName(), f
						.getEntryPoint(), null, f.getSymbol().getSource(),
						true, true);
				cf.applyTo(p);
			}
			bmgr.removeBookmark(bm);
			bmgr.setBookmark(ba, "Analysis", "Cleanup",
					"Converted invalid pointer to code");
		}
	}
}
