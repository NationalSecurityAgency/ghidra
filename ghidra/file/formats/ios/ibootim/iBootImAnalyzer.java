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
package ghidra.file.formats.ios.ibootim;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
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

public class iBootImAnalyzer extends FileFormatAnalyzer implements AnalysisWorker {

	@Override
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

		iBootImHeader header = new iBootImHeader(provider);

		if (!header.getSignature().equals(iBootImConstants.SIGNATURE)) {
			return false;
		}

		DataType headerDataType = header.toDataType();

		Data headerData = createData(program, address, headerDataType);

		createFragment(program, headerDataType.getName(), headerData.getMinAddress(),
			headerData.getMaxAddress().add(1));

		changeDataSettings(program, monitor);

		removeEmptyFragments(program);
		return true;
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	public boolean canAnalyze(Program program) {
		return iBootImUtil.isiBootIm(program);
	}

	public boolean getDefaultEnablement(Program program) {
		return iBootImUtil.isiBootIm(program);
	}

	public String getDescription() {
		return "Annotates an iBoot Image (iBootIm) file.";
	}

	public String getName() {
		return "iBoot Image (iBootIm) Annotation";
	}

	public boolean isPrototype() {
		return true;
	}
}
