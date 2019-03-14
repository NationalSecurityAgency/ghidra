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
package ghidra.file.formats.ios.dmg;

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

import java.util.Arrays;

public class DmgAnalyzer extends FileFormatAnalyzer implements AnalysisWorker {

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
		BinaryReader reader = new BinaryReader(provider, false);

		DmgHeader header = new DmgHeaderV2(reader);

		if (!Arrays.equals(header.getSignature(), DmgConstants.DMG_MAGIC_BYTES_v2)) {
			return false;
		}

		DataType headerDataType = header.toDataType();

		Data headerData = createData(program, address, headerDataType);

		createFragment(program, headerDataType.getName(), headerData.getMinAddress(),
			headerData.getMaxAddress().add(1));
		return true;
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	public boolean canAnalyze(Program program) {
		return DmgUtil.isDMG(program);
	}

	public boolean getDefaultEnablement(Program program) {
		return DmgUtil.isDMG(program);
	}

	public String getDescription() {
		return "Annotates an DMG file.";
	}

	public String getName() {
		return "DMG";
	}

	public boolean isPrototype() {
		return true;
	}
}
