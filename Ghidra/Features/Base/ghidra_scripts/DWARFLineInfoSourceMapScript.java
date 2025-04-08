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
// A source file that is relative after path normalization will have all leading "."
// and "/../" entries stripped and then be placed under an artificial directory.
// Note that you can run this script on a program that has already been analyzed by the
// DWARF analyzer.
//@category DWARF
import java.io.IOException;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine.SourceFileAddr;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory;
import ghidra.framework.store.LockException;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.program.model.address.*;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.util.Msg;
import ghidra.util.SourceFileUtils;
import ghidra.util.exception.CancelledException;

public class DWARFLineInfoSourceMapScript extends GhidraScript {
	public static final int ENTRY_MAX_LENGTH = 1000;
	private static final int MAX_ERROR_MSGS_TO_DISPLAY = 25;
	private static final int MAX_WARNING_MSGS_TO_DISPLAY = 25;
	private static final String COMPILATION_ROOT_DIRECTORY = DWARFImporter.DEFAULT_COMPILATION_DIR;
	private int numErrors;
	private int numWarnings;

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
		List<DWARFCompilationUnit> compUnits = dprog.getCompilationUnits();
		SourceFileManager sourceManager = currentProgram.getSourceFileManager();
		List<SourceFileAddr> sourceInfo = new ArrayList<>();
		monitor.initialize(compUnits.size(), "DWARF: Reading Source Map Info");
		for (DWARFCompilationUnit cu : compUnits) {
			monitor.increment();
			sourceInfo.addAll(cu.getLine().getAllSourceFileAddrInfo(cu, reader));
		}
		monitor.setIndeterminate(true);
		monitor.setMessage("Sorting " + sourceInfo.size() + " entries");
		sourceInfo.sort((i, j) -> Long.compareUnsigned(i.address(), j.address()));
		monitor.setIndeterminate(false);
		monitor.initialize(sourceInfo.size(), "DWARF: Applying Source Map Info");
		Map<SourceFileAddr, SourceFile> sfasToSourceFiles = new HashMap<>();
		Set<SourceFileAddr> badSfas = new HashSet<>();
		AddressSet warnedAddresses = new AddressSet();
		for (int i = 0; i < sourceInfo.size(); i++) {
			monitor.increment(1);
			SourceFileAddr sourceFileAddr = sourceInfo.get(i);
			if (sourceFileAddr.isEndSequence()) {
				continue;
			}
			if (sourceFileAddr.fileName() == null) {
				continue;
			}

			if (badSfas.contains(sourceFileAddr)) {
				continue;
			}

			Address addr = dprog.getCodeAddress(sourceFileAddr.address());
			if (warnedAddresses.contains(addr)) {
				continue; // only warn once per address
			}

			if (!currentProgram.getMemory().getExecuteSet().contains(addr)) {
				if (numWarnings++ < MAX_WARNING_MSGS_TO_DISPLAY) {
					printerr(
						"entry for non-executable address; skipping: file %s line %d address: %s %x"
						.formatted(sourceFileAddr.fileName(), sourceFileAddr.lineNum(),
							addr.toString(), sourceFileAddr.address()));
				}
				warnedAddresses.add(addr);
				continue;
			}

			long length = getLength(i, sourceInfo);
			if (length < 0) {
				if (numWarnings++ < MAX_WARNING_MSGS_TO_DISPLAY) {
					println(
						"Error computing entry length for file %s line %d address %s %x; replacing" +
							" with length 0 entry".formatted(sourceFileAddr.fileName(),
								sourceFileAddr.lineNum(), addr.toString(),
								sourceFileAddr.address()));
				}
			}
			if (length > ENTRY_MAX_LENGTH) {
				if (numWarnings++ < MAX_WARNING_MSGS_TO_DISPLAY) {
					println(
						("entry for file %s line %d address: %s %x length %d too large, replacing " +
								"with length 0 entry").formatted(sourceFileAddr.fileName(),
									sourceFileAddr.lineNum(), addr.toString(), sourceFileAddr.address(),
									length));
				}
			}


			SourceFile source = sfasToSourceFiles.get(sourceFileAddr);
			if (source == null) {
				try {
					String path = SourceFileUtils.normalizeDwarfPath(sourceFileAddr.fileName(),
						COMPILATION_ROOT_DIRECTORY);
					SourceFileIdType type =
						sourceFileAddr.md5() == null ? SourceFileIdType.NONE : SourceFileIdType.MD5;
					source = new SourceFile(path, type, sourceFileAddr.md5());
					sourceManager.addSourceFile(source);
					sfasToSourceFiles.put(sourceFileAddr, source);
				}
				catch (IllegalArgumentException e) {
					if (numErrors++ < MAX_ERROR_MSGS_TO_DISPLAY) {
						printerr("Exception creating source file %s".formatted(e.getMessage()));
					}
					badSfas.add(sourceFileAddr);
					continue;
				}
			}
			try {
				sourceManager.addSourceMapEntry(source, sourceFileAddr.lineNum(), addr, length);
			}
			catch (IllegalArgumentException e) {
				if (numErrors++ < MAX_ERROR_MSGS_TO_DISPLAY) {
					printerr(e.getMessage());
				}
				continue;
			}
			entryCount++;
		}
		if (numWarnings >= MAX_WARNING_MSGS_TO_DISPLAY) {
			println("Additional warning messages suppressed");
		}
		if (numErrors >= MAX_ERROR_MSGS_TO_DISPLAY) {
			println("Additional error messages suppressed");
		}
		println("Added " + entryCount + " source map entries");
		printf("There were %d errors and %d warnings\n", numErrors,numWarnings);
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
