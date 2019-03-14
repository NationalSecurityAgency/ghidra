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
package ghidra.file.formats.ios.generic;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class iOS_FixupArmSymbolsAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Apple iOS ARM Symbol Fixup";
	private static final String DESCRIPTION =
		"Moves the pre-defined ARM symbols to image base of the iOS binary.";

	public iOS_FixupArmSymbolsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return isBoot(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isBoot(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator symbolIterator = symbolTable.getSymbolIterator();
		while (symbolIterator.hasNext()) {
			Symbol symbol = symbolIterator.next();
			if (symbol.isPinned()) {
				symbol.setPinned(false);
			}
		}
		return false;
	}

	private boolean isBoot(Program program) {
		if (program == null) {
			return false;
		}
		Language language = program.getLanguage();
		if (language == null) {
			return false;
		}
		Processor processor = language.getProcessor();
		if (processor == null) {
			return false;
		}
		if (!processor.equals(Processor.findOrPossiblyCreateProcessor("ARM"))) {
			return false;
		}

		Address minAddress = program.getMinAddress();
		if (minAddress == null) {//program has 0 memory blocks
			return false;
		}

		Address address = null;
		try {
			address = minAddress.add(0x200);
		}
		catch (Exception e) {
			return false;//program memory is too small
		}
		if (address == null) {
			return false;
		}

		Memory memory = program.getMemory();
		byte[] bytes = new byte[0x40];
		try {
			memory.getBytes(address, bytes);
		}
		catch (MemoryAccessException e) {
		}

		String string = new String(bytes).trim();

		if (string.indexOf("Apple") != -1) {
			if (string.startsWith("SecureROM")) {
				return true;
			}
			if (string.startsWith("LLB")) {
				return true;
			}
			if (string.startsWith("iBoot")) {
				return true;
			}
			if (string.startsWith("iBEC")) {
				return true;
			}
			if (string.startsWith("iBSS")) {
				return true;
			}
		}

		return false;
	}
}
