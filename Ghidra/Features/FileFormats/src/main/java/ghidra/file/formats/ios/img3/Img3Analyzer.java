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
package ghidra.file.formats.ios.img3;

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

import java.util.List;

public class Img3Analyzer extends FileFormatAnalyzer implements AnalysisWorker {

	public boolean canAnalyze(Program program) {
		return Img3Util.isIMG3(program);
	}

	public boolean getDefaultEnablement(Program program) {
		return Img3Util.isIMG3(program);
	}

	public String getDescription() {
		return "Annotates an IMG3 file.";
	}

	public String getName() {
		return "IMG3 Annotation";
	}

	public boolean isPrototype() {
		return true;
	}

	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		return manager.scheduleWorker(this, null, false, monitor);
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext, TaskMonitor monitor)
			throws Exception, CancelledException {
		Address address = program.getMinAddress();

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		BinaryReader reader = new BinaryReader(provider, true);

		Img3 header = new Img3(reader);

		if (!header.getMagic().equals(Img3Constants.IMG3_SIGNATURE)) {
			return false;
		}

		DataType headerDataType = header.toDataType();

		Data headerData = createData(program, address, headerDataType);

		createFragment(program, headerDataType.getName(), headerData.getMinAddress(),
			headerData.getMaxAddress().add(1));

		Address tagAddress = headerData.getMaxAddress().add(1);
		applyTags(program, header, tagAddress, monitor);

		changeDataSettings(program, monitor);

		removeEmptyFragments(program);
		return true;
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	private void applyTags(Program program, Img3 header, Address tagAddress, TaskMonitor monitor)
			throws Exception {
		List<AbstractImg3Tag> tags = header.getTags();
		for (AbstractImg3Tag tag : tags) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = tag.toDataType();
			setPlateComment(program, tagAddress, tag.getMagic());
			createData(program, tagAddress, dt);
			createFragment(program, tag.getMagic(), tagAddress,
				tagAddress.add(tag.getTotalLength()));
			tagAddress = tagAddress.add(tag.getTotalLength());
		}
	}
}
