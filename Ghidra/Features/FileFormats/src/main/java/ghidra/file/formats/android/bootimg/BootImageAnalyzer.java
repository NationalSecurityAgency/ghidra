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
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
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
		return "Android Boot, Recovery, or Vendor Image Annotation";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}

	@Override
	public String getDescription() {
		return "Annotates Android Boot, Recovery, or Vendor Image files.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			return BootImageUtil.isBootImage(program) || BootImageUtil.isVendorBootImage(program);
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

	private MessageLog messageLog;

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		this.messageLog = log;
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		return manager.scheduleWorker(this, null, false, monitor);
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor monitor) throws Exception, CancelledException {

		Address address = program.getMinAddress();

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		BinaryReader reader = new BinaryReader(provider, true);

		if (BootImageUtil.isBootImage(program)) {

			BootImageHeader header = BootImageHeaderFactory.getBootImageHeader(reader);

			if (!BootImageConstants.BOOT_MAGIC.equals(header.getMagic())) {
				return false;
			}

			DataType headerDataType = header.toDataType();

			Data headerData = createData(program, address, headerDataType);

			if (headerData == null) {
				messageLog.appendMsg("Unable to create header data.");
				return false;
			}

			createFragment(program, headerDataType.getName(), toAddr(program, 0),
				toAddr(program, header.getPageSize()));

			if (header.getKernelSize() > 0) {
				Address start = toAddr(program, header.getKernelOffset());
				Address end = toAddr(program, header.getKernelOffset() + header.getKernelSize());
				createFragment(program, BootImageConstants.KERNEL, start, end);
			}

			if (header.getRamdiskSize() > 0) {
				Address start = toAddr(program, header.getRamdiskOffset());
				Address end = toAddr(program, header.getRamdiskOffset() + header.getRamdiskSize());
				createFragment(program, BootImageConstants.RAMDISK, start, end);
			}

			if (header.getSecondSize() > 0) {
				Address start = toAddr(program, header.getSecondOffset());
				Address end = toAddr(program, header.getSecondOffset() + header.getSecondSize());
				createFragment(program, BootImageConstants.SECOND_STAGE, start, end);
			}

			changeDataSettings(program, monitor);
		}
		else if (BootImageUtil.isVendorBootImage(program)) {
			VendorBootImageHeader header =
				VendorBootImageHeaderFactory.getVendorBootImageHeader(reader);

			if (!header.getMagic().equals(BootImageConstants.VENDOR_BOOT_MAGIC)) {
				return false;
			}

			DataType headerDataType = header.toDataType();

			Data headerData = createData(program, address, headerDataType);

			if (headerData == null) {
				messageLog.appendMsg("Unable to create header data.");
			}

			createFragment(program, headerDataType.getName(), toAddr(program, 0),
				toAddr(program, headerData.getLength()));

			if (header.getVendorRamdiskSize() > 0) {
				Address start = toAddr(program, header.getVendorRamdiskOffset());
				Address end = toAddr(program,
					header.getVendorRamdiskOffset() + header.getVendorRamdiskSize());
				createFragment(program, BootImageConstants.RAMDISK, start, end);
			}

			if (header.getDtbSize() > 0) {
				Address start = toAddr(program, header.getDtbOffset());
				Address end = toAddr(program, header.getDtbOffset() + header.getDtbSize());
				createFragment(program, BootImageConstants.DTB, start, end);
			}
		}

		removeEmptyFragments(program);

		return true;
	}

	@Override
	public String getWorkerName() {
		return "BootImageAnalyzer";
	}
}
