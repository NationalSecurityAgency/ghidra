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
package ghidra.file.formats.android.bootimg;

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

public class BootImageAnalyzer extends FileFormatAnalyzer implements AnalysisWorker {

	@Override
	public String getName() {
		return "Android Boot or Recovery Image Annotation";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}

	@Override
	public String getDescription() {
		return "Annotates Android Boot and Recovery Image files.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			return BootImageUtil.isBootImage(program);
		}
		catch (Exception e) {
			// not a boot image
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

		BootImage header = new BootImage(reader);

		if (!header.getMagic().equals(BootImageConstants.BOOT_IMAGE_MAGIC)) {
			return false;
		}

		DataType headerDataType = header.toDataType();

		Data headerData = createData(program, address, headerDataType);

		if (headerData == null) {
			log.appendMsg("Unable to create header data.");
		}

		createFragment(program, headerDataType.getName(), toAddr(program, 0),
			toAddr(program, header.getPageSize()));

		if (header.getKernelSize() > 0) {
			Address start = toAddr(program, header.getKernelOffset());
			Address end = toAddr(program, header.getKernelOffset() + header.getKernelSize());
			createFragment(program, BootImageConstants.KERNEL, start, end);
		}

		if (header.getRamDiskSize() > 0) {
			Address start = toAddr(program, header.getRamDiskOffset());
			Address end = toAddr(program, header.getRamDiskOffset() + header.getRamDiskSize());
			createFragment(program, BootImageConstants.RAMDISK, start, end);
		}

		if (header.getSecondStageSize() > 0) {
			Address start = toAddr(program, header.getSecondStageOffset());
			Address end =
				toAddr(program, header.getSecondStageOffset() + header.getSecondStageSize());
			createFragment(program, BootImageConstants.SECOND_STAGE, start, end);
		}

		changeDataSettings(program, monitor);

		removeEmptyFragments(program);

		return true;
	}

	@Override
	public String getWorkerName() {
		return "BootImageAnalyzer";
	}
}
