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
package ghidra.file.formats.yaffs2;

import java.util.Arrays;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// analyzer for YAFFS2 image files
// places header and extended tags (footer) structures, and annotates data locations
public class YAFFS2Analyzer extends FileFormatAnalyzer implements AnalysisWorker {

	@Override
	public String getName() {
		return "YAFFS2 Image Annotation (used in Android System and Userdata image files)";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}

	@Override
	public String getDescription() {
		return "Annotates YAFFS2 Image files (used in Android System and UserData Images.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			return YAFFS2Utils.isYAFFS2Image(program);
		}
		catch (Exception e) {
			// not a yaffs2 image
		}
		return false;
	}

	@Override
	public boolean isPrototype() {
		return true;
	}

	private MessageLog log;

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		this.log = log;
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		return manager.scheduleWorker(this, null, false, monitor);
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext, TaskMonitor monitor)
			throws Exception, CancelledException {

		Address address = program.getMinAddress();

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		BinaryReader reader = new BinaryReader(provider, true);

		int index = 0;
		byte[] block;
		long lastObjectType = 3;		// initialized to object type 3 (a directory)
		YAFFS2Header header;
		YAFFS2ExtendedTags tags;
		YAFFS2Data dataBlock;

		// loop over reader by record length (2112 bytes) and lay down the appropriate structures
		while (index < reader.length()) {
			if (monitor.isCancelled()) {
				break;
			}

			// grab next block of data
			block = reader.readByteArray(index, YAFFS2Constants.RECORD_SIZE);

			// header structure
			if (lastObjectType != 1) {
				header =
					new YAFFS2Header(Arrays.copyOfRange(block, 0, YAFFS2Constants.DATA_BUFFER_SIZE));
				DataType headerDataType = header.toDataType();
				Data headerData = createData(program, address.add(index), headerDataType);
				if (headerData == null) {
					log.appendMsg("Unable to create header.");
				}
				lastObjectType = header.getObjectType();
			}
			// data block structure
			else {
				dataBlock =
					new YAFFS2Data(Arrays.copyOfRange(block, 0, YAFFS2Constants.DATA_BUFFER_SIZE));
				DataType dataBlockDataType = dataBlock.toDataType();
				Data dataBlockData = createData(program, address.add(index), dataBlockDataType);
				if (dataBlockData == null) {
					log.appendMsg("Unable to create data block.");
				}
			}

			// tags structure
			tags =
				new YAFFS2ExtendedTags(Arrays.copyOfRange(block, YAFFS2Constants.DATA_BUFFER_SIZE,
					YAFFS2Constants.RECORD_SIZE - 1));
			DataType tagsDataType = tags.toDataType();

			// create data for this block
			Data tagsData =
				createData(program, address.add(index + YAFFS2Constants.DATA_BUFFER_SIZE),
					tagsDataType);
			if (tagsData == null) {
				log.appendMsg("Unable to create tags (footer).");
			}

			//increment to next record
			index += YAFFS2Constants.RECORD_SIZE;
		}

		changeDataSettings(program, monitor);
		removeEmptyFragments(program);

		return true;

	}

	@Override
	public String getWorkerName() {
		return "YAFFS2Analyzer";
	}

}
