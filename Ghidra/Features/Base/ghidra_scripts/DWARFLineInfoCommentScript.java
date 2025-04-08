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
// Adds DWARF source file line number info to the current binary as EOL comments.
// Note that you can run this script on a program that has already been analyzed by the
// DWARF analyzer.
//@category DWARF
import java.io.IOException;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine.SourceFileAddr;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class DWARFLineInfoCommentScript extends GhidraScript {
	@Override
	protected void run() throws Exception {
		DWARFSectionProvider dsp =
			DWARFSectionProviderFactory.createSectionProviderFor(currentProgram, monitor);
		if (dsp == null) {
			printerr("Unable to find DWARF information");
			return;
		}

		DWARFImportOptions importOptions = new DWARFImportOptions();
		try (DWARFProgram dprog = new DWARFProgram(currentProgram, importOptions, monitor, dsp)) {
			dprog.init(monitor);
			addSourceLineInfo(dprog);
		}
	}

	private void addSourceLineInfo(DWARFProgram dprog) throws CancelledException, IOException {
		BinaryReader reader = dprog.getDebugLineBR();
		if (reader == null) {
			return;
		}
		int count = 0;
		monitor.initialize(reader.length(), "DWARF Source Line Info");
		List<DWARFCompilationUnit> compUnits = dprog.getCompilationUnits();
		for (DWARFCompilationUnit cu : compUnits) {
			try {
				monitor.checkCancelled();
				monitor.setProgress(cu.getLine().getStartOffset());
				List<SourceFileAddr> allSFA = cu.getLine().getAllSourceFileAddrInfo(cu, reader);
				for (SourceFileAddr sfa : allSFA) {
					Address addr = dprog.getCodeAddress(sfa.address());
					DWARFUtil.appendComment(currentProgram, addr, CommentType.EOL, "",
						"%s:%d".formatted(sfa.fileName(), sfa.lineNum()), ";");
					count++;
				}
			}
			catch (IOException e) {
				Msg.error(this,
					"Failed to read DWARF line info for cu %d".formatted(cu.getUnitNumber()), e);
			}
		}
		println("Marked up " + count + " locations with source info");
	}
}
