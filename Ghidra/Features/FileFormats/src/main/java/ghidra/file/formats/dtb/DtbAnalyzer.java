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
package ghidra.file.formats.dtb;

import java.util.Arrays;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class DtbAnalyzer extends FileFormatAnalyzer {

	@Override
	public String getName() {
		return "Device Tree (DTB/DTBO) Analyzer";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Analyzes Device Tree (DTB/DTBO) files.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			if (DtbUtil.isCorrectLoader(program)) {
				Address address = toAddr(program, 0);
				byte[] magicBytes = new byte[DtConstants.DT_TABLE_MAGIC_SIZE];
				program.getMemory().getBytes(address, magicBytes);
				return Arrays.equals(magicBytes, DtConstants.DT_TABLE_MAGIC_BYTES);
			}
		}
		catch (Exception e) {
			//ignore
		}
		return false;
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {

		if (!DtbUtil.isCorrectProcessor(program, log)) {
			return false;
		}

		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());

		DtTableHeader header = new DtTableHeader(reader);
		DataType headerDataType = header.toDataType();
		createData(program, program.getMinAddress(), headerDataType);
		createFragment(program, "DtTableHeader", program.getMinAddress(),
			program.getMinAddress().add(headerDataType.getLength()));

		Address entryStartAddress = toAddr(program, header.getDtEntriesOffset());

		monitor.initialize(header.getEntries().size());
		for (int i = 0; i < header.getEntries().size(); ++i) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			DtTableEntry entry = header.getEntries().get(i);
			Data entryData = createData(program, entryStartAddress, entry.toDataType());
			Address entryEndAddress = entryStartAddress.add(header.getDtEntrySize());
			createFragment(program, "DtTableEntry_" + i, entryStartAddress, entryEndAddress);
			entryStartAddress = entryEndAddress;

			Data offsetData = entryData.getComponent(1);//dt_offset field
			program.getReferenceManager()
					.addMemoryReference(offsetData.getMinAddress(),
						toAddr(program, entry.getDtOffset()), RefType.DATA, SourceType.ANALYSIS, 0);

			Address entryDataStartAddress = toAddr(program, entry.getDtOffset());
			Address entryDataEndAddress = entryDataStartAddress.add(entry.getDtSize());
			createFragment(program, "DtTableEntry_" + i, entryDataStartAddress,
				entryDataEndAddress);

			FdtHeader fdtHeader = entry.getFdtHeader();
			if (fdtHeader != null) {
				fdtHeader.markup(toAddr(program, entry.getDtOffset()), program, monitor, log);
			}
		}

		return true;
	}

}
