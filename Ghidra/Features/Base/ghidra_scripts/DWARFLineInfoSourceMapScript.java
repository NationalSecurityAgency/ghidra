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
// Adds DWARF source file line number info to the current program as source map entries.
// Note that you can run this script on a program that has already been analyzed by the
// DWARF analyzer.
//@category DWARF
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine.SourceFileAddr;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory;
import ghidra.framework.store.LockException;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class DWARFLineInfoSourceMapScript extends GhidraScript {
	public static final int ENTRY_MAX_LENGTH = 1000;

	@Override
	protected void run() throws Exception {

		if (!currentProgram.hasExclusiveAccess()) {
			Msg.showError(this, null, "Exclusive Access Required",
				"Must have exclusive access to a program to add source map info");
			return;
		}
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

	private void addSourceLineInfo(DWARFProgram dprog)
			throws CancelledException, IOException, LockException, AddressOverflowException {
		BinaryReader reader = dprog.getDebugLineBR();
		if (reader == null) {
			popup("Unable to get reader for debug line info");
			return;
		}
		int entryCount = 0;
		monitor.initialize(reader.length(), "DWARF Source Map Info");
		List<DWARFCompilationUnit> compUnits = dprog.getCompilationUnits();
		SourceFileManager sourceManager = currentProgram.getSourceFileManager();
		List<SourceFileAddr> sourceInfo = new ArrayList<>();
		for (DWARFCompilationUnit cu : compUnits) {
			sourceInfo.addAll(cu.getLine().getAllSourceFileAddrInfo(cu, reader));
		}
		sourceInfo.sort((i, j) -> Long.compareUnsigned(i.address(), j.address()));
		monitor.initialize(sourceInfo.size());
		for (int i = 0; i < sourceInfo.size(); i++) {
			monitor.checkCancelled();
			monitor.increment(1);
			SourceFileAddr sourceFileAddr = sourceInfo.get(i);
			if (sourceFileAddr.isEndSequence()) {
				continue;
			}
			Address addr = dprog.getCodeAddress(sourceFileAddr.address());
			if (!currentProgram.getMemory().getExecuteSet().contains(addr)) {
				printerr(
					"entry for non-executable address; skipping: file %s line %d address: %s %x"
							.formatted(sourceFileAddr.fileName(), sourceFileAddr.lineNum(),
								addr.toString(), sourceFileAddr.address()));
				continue;
			}

			long length = getLength(i, sourceInfo);
			if (length < 0) {
				println(
					"Error computing entry length for file %s line %d address %s %x; replacing" +
						" with length 0 entry".formatted(sourceFileAddr.fileName(),
							sourceFileAddr.lineNum(), addr.toString(), sourceFileAddr.address()));
				length = 0;
			}
			if (length > ENTRY_MAX_LENGTH) {
				println(
					("entry for file %s line %d address: %s %x length %d too large, replacing " +
						"with length 0 entry").formatted(sourceFileAddr.fileName(),
							sourceFileAddr.lineNum(), addr.toString(), sourceFileAddr.address(),
							length));
				length = 0;
			}
			if (sourceFileAddr.fileName() == null) {
				continue;
			}
			SourceFile source = null;
			try {
				SourceFileIdType type =
					sourceFileAddr.md5() == null ? SourceFileIdType.NONE : SourceFileIdType.MD5;
				source = new SourceFile(sourceFileAddr.fileName(), type, sourceFileAddr.md5());
				sourceManager.addSourceFile(source);
			}
			catch (IllegalArgumentException e) {
				printerr("Exception creating source file %s".formatted(e.getMessage()));
				continue;
			}
			try {
				sourceManager.addSourceMapEntry(source, sourceFileAddr.lineNum(), addr, length);
			}
			catch (IllegalArgumentException e) {
				printerr(e.getMessage());
				continue;
			}
			entryCount++;
		}
		println("Added " + entryCount + " source map entries");
	}

	private long getLength(int i, List<SourceFileAddr> allSFA) {
		SourceFileAddr iAddr = allSFA.get(i);
		long iOffset = iAddr.address();
		for (int j = i + 1; j < allSFA.size(); j++) {
			SourceFileAddr current = allSFA.get(j);
			long currentAddr = current.address();
			if (current.isEndSequence()) {
				return currentAddr + 1 - iOffset;
			}
			if (currentAddr != iOffset) {
				return currentAddr - iOffset;
			}
		}
		return -1;
	}
}
