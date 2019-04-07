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
package ghidra.app.util.bin.format.pef;

import ghidra.app.cmd.label.AddUniqueLabelCmd;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.List;

/**
 * See Apple's -- PEFBinaryFormat.h
 */
public class RelocLgByImport extends Relocation {
	private int index;

	RelocLgByImport(BinaryReader reader) throws IOException {
		int value = reader.readNextShort() & 0xffff;

		opcode  =  (value & 0xfc00) >> 10;
		index   =  (value & 0x03ff) << 16;
		index  |= reader.readNextShort();
	}

	@Override
	public boolean isMatch() {
		return opcode == 0x29;
	}

	@Override
	public int getSizeInBytes() {
		return 4;
	}

	public int getIndex() {
		return index;
	}

	@Override
	public void apply(ImportStateCache importState, RelocationState relocState, 
			ContainerHeader header, Program program, MessageLog log, TaskMonitor monitor) {

		LoaderInfoHeader loader = header.getLoader();
		ImportedLibrary library = loader.findLibrary(index);
		List<ImportedSymbol> importedSymbols = loader.getImportedSymbols();
		ImportedSymbol importedSymbol = importedSymbols.get(index);

		String name = SymbolUtilities.replaceInvalidChars(importedSymbol.getName(), true);
		Address address = relocState.getRelocationAddress();
		Namespace tvectNamespace = importState.getTVectNamespace();
		AddUniqueLabelCmd cmd = new AddUniqueLabelCmd(address, name, tvectNamespace, SourceType.IMPORTED);
		if (!cmd.applyTo(program)) {
			log.appendMsg(cmd.getStatusMsg());
		}

		Symbol symbol = importState.getSymbol(name, library);
		relocState.fixupMemory(address, symbol.getAddress(), log);

		relocState.incrementRelocationAddress(4);
		relocState.setImportIndex(index + 1);
	}
}
