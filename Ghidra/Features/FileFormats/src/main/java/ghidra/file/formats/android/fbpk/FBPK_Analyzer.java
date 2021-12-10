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

import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FBPK_Analyzer extends AbstractAnalyzer {

	public FBPK_Analyzer() {
		super("Android FBPK Analyzer", "Annotates Android FBPK Files", AnalyzerType.BYTE_ANALYZER);
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
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Address headerAddress = program.getMinAddress();
		ByteProvider provider = new MemoryByteProvider(program.getMemory(), headerAddress);
		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());
		try {
			FBPK header = new FBPK(reader);
			DataType headerDataType = header.toDataType();
			Data headerData = program.getListing().createData(headerAddress, headerDataType);
			if (headerData == null) {
				log.appendMsg("Unable to apply FBPK data, stopping - " + headerAddress);
				return false;
			}

			Address address = headerAddress.add(headerDataType.getLength());

			List<FBPK_Partition> partitions = header.getPartitions();
			for (int i = 0; i < partitions.size(); ++i) {
				FBPK_Partition partition = partitions.get(i);

				DataType partitionDataType = partition.toDataType();
				Data partitionData = program.getListing().createData(address, partitionDataType);
				if (partitionData == null) {
					log.appendMsg("Unable to apply partition data, stopping - " + address);
					return false;
				}
				program.getListing()
						.setComment(address, CodeUnit.PLATE_COMMENT,
							partition.getName() + " - " + i);
				address = address.add(partitionDataType.getLength());

				if (partition.isDirectory()) {
					if (!processFBPT(program, address, partition, monitor, log)) {
						return false;
					}
				}
				else if (partition.isFile()) {
					//unused, but leave as placeholder for future
				}

				address = address.getNewAddress(partition.getOffsetToNextPartitionTable());
			}

			return true;
		}
		catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

	private boolean processFBPT(Program program, Address address, FBPK_Partition partition,
			TaskMonitor monitor, MessageLog log) throws Exception {

		FBPT fbpt = partition.getFBPT();
		DataType fbptDataType = fbpt.toDataType();
		Data fbptData = program.getListing().createData(address, fbptDataType);
		if (fbptData == null) {
			log.appendMsg("Unable to apply FBPT data, stopping - " + address);
			return false;
		}
		String comment = "FBPT" + "\n" + "Num of entries: " + fbpt.getNEntries();
		program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);
		address = address.add(fbptDataType.getLength());

		return processFbPtEntries(program, address, fbpt, monitor, log);
	}

	private boolean processFbPtEntries(Program program, Address address, FBPT fbpt,
			TaskMonitor monitor, MessageLog log) throws Exception {
		for (int i = 0; i < fbpt.getEntries().size(); ++i) {
			FBPT_Entry entry = fbpt.getEntries().get(i);
			monitor.checkCanceled();
			DataType entryDataType = entry.toDataType();
			Data entryData = program.getListing().createData(address, entryDataType);
			if (entryData == null) {
				log.appendMsg("Unable to apply FBPT Entry data, stopping - " + address);
				return false;
			}
			program.getListing()
					.setComment(address, CodeUnit.PLATE_COMMENT, entry.getName() + " - " + i);
			address = address.add(entryDataType.getLength());
		}
		return true;
	}

}
