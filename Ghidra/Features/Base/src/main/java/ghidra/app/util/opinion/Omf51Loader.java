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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.omf.*;
import ghidra.app.util.bin.format.omf.omf51.Omf51RecordFactory;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for OMF-51 files
 */
public class Omf51Loader extends AbstractProgramWrapperLoader {
	public final static String OMF51_NAME = "Object Module Format (OMF-51)";
	public final static long MIN_BYTE_LENGTH = 11;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		AbstractOmfRecordFactory factory = new Omf51RecordFactory(provider);
		try {
			OmfRecord first = factory.readNextRecord();
			if (factory.getStartRecordTypes().contains(first.getRecordType()) &&
				first.validCheckSum()) {
				List<QueryResult> results = QueryOpinionService.query(getName(), "8051", null);
				for (QueryResult result : results) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
				if (loadSpecs.isEmpty()) {
					loadSpecs.add(new LoadSpec(this, 0, true));
				}
			}
		}
		catch (IOException | OmfException e) {
			// that's ok, not an OMF-51
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AbstractOmfRecordFactory factory = new Omf51RecordFactory(provider);
		try {
			List<OmfRecord> records = OmfUtils.readRecords(factory);
			markupRecords(program, fileBytes, records, log, monitor);
		}
		catch (OmfException e) {
			throw new IOException(e);
		}
	}

	private void markupRecords(Program program, FileBytes fileBytes, List<OmfRecord> records,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up records...");
		int size = records.stream().mapToInt(r -> r.getRecordLength() + 3).sum();
		try {
			Address recordSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"RECORDS", recordSpaceAddr, fileBytes, 0, size, "", "", false, false, false, log);
			Address start = headerBlock.getStart();

			for (OmfRecord record : records) {
				Data d = DataUtilities.createData(program, start.add(record.getRecordOffset()),
					record.toDataType(), -1, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				StructConverter.setEndian(d, false);
			}
		}
		catch (Exception e) {
			log.appendMsg("Failed to markup records");
		}
	}

	@Override
	public String getName() {
		return OMF51_NAME;
	}
}
