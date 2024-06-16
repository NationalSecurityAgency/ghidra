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
package ghidra.file.formats.android.fbpk;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class FBPK_Analyzer extends FileFormatAnalyzer {

	@Override
	public String getName() {
		return "Android FBPK Analyzer";
	}

	@Override
	public String getDescription() {
		return "Annotates Android FBPK Files";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return FBPK_Constants.isFBPK(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return FBPK_Constants.isFBPK(program);
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {

		Address headerAddress = program.getMinAddress();
		ByteProvider provider = MemoryByteProvider.createProgramHeaderByteProvider(program, false);

		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());
		try {
			FBPK header = FBPK_Factory.getFBPK(reader);
			DataType headerDataType = header.toDataType();
			Data headerData = program.getListing().createData(headerAddress, headerDataType);
			if (headerData == null) {
				log.appendMsg("Unable to apply FBPK data, stopping - " + headerAddress);
				return false;
			}
			Address address = headerAddress.add(headerDataType.getLength());

			monitor.initialize(header.getPartitions().size());
			monitor.setMessage("Marking up paritions...");
			for (FBPK_Partition partition : header.getPartitions()) {
				monitor.checkCancelled();
				monitor.incrementProgress(1);
				partition.markup(program, address, monitor, log);
				if (partition.getOffsetToNextPartitionTable() > 0) {
					address = address.getNewAddress(partition.getOffsetToNextPartitionTable());
				}
				else {
					address = address.add(partition.getHeaderSize());
				}
			}

			return true;
		}
		catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

}
