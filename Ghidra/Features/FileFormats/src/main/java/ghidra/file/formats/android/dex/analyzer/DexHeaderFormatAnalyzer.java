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
package ghidra.file.formats.android.dex.analyzer;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.cdex.CDexConstants;
import ghidra.file.formats.android.dex.format.DexConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DexHeaderFormatAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {

		Address baseAddress = toAddr(program, 0x0);

		if (getDataAt(program, baseAddress) != null) {
			log.appendMsg("data already exists.");
			return true;
		}

		DexHeaderFormatMarkup markup = new DexHeaderFormatMarkup(program, baseAddress);
		markup.markup(monitor, log);

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		return DexConstants.isDexFile(provider) || CDexConstants.isCDEX(program);
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.BYTE_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Android Dalvik EXecutable (DEX) / Compact DEX (CDEX) Header Format";
	}

	@Override
	public String getName() {
		return "Android DEX/CDEX Header Format";
	}

	@Override
	public AnalysisPriority getPriority() {
		return new AnalysisPriority(0);
	}

	@Override
	public boolean isPrototype() {
		return false;
	}
}
