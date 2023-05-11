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
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class FdtAnalyzer extends FileFormatAnalyzer {

	@Override
	public String getName() {
		return "Flattened Device Tree (FDT/DTB/DTBO) Analyzer";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Analyzes Flattened Device Tree (FDT) files.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			if (DtbUtil.isCorrectLoader(program)) {
				Address address = toAddr(program, 0);
				byte[] magicBytes = new byte[FdtConstants.FDT_MAGIC_SIZE];
				program.getMemory().getBytes(address, magicBytes);
				return Arrays.equals(magicBytes, FdtConstants.FDT_MAGIC_BYTES);
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

		try (ByteProvider provider =
			MemoryByteProvider.createProgramHeaderByteProvider(program, true)) {

			BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());

			Address address = program.getMinAddress();

			while (true) {
				monitor.checkCanceled();

				if (address.compareTo(program.getMaxAddress()) >= 0) {
					break;
				}

				reader.setPointerIndex(address.getOffset());

				FdtHeader fdtHeader = new FdtHeader(reader);
				fdtHeader.markup(address, program, monitor, log);

				// look for next FDT entry
				address = address.add(fdtHeader.getTotalSize());
			}
		}
		return true;
	}

}
