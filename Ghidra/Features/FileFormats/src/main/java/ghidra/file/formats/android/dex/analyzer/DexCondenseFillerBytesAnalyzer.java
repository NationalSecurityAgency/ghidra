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
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.*;
import ghidra.program.model.data.AlignmentDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DexCondenseFillerBytesAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		AlignmentDataType alignmentDataType = new AlignmentDataType();

		Address address = toAddr(program, DexUtil.METHOD_ADDRESS);
		MemoryBlock block = program.getMemory().getBlock(address);

		if (block == null) {
			log.appendMsg("Can't locate block with method byte code!");
			return false;
		}

		AddressSet blockSet = new AddressSet(block.getStart(), block.getEnd());

		AddressSetView undefinedSet =
			program.getListing().getUndefinedRanges(blockSet, true, monitor);

		monitor.setMaximum(undefinedSet.getNumAddressRanges());
		monitor.setProgress(0);
		monitor.setMessage("DEX: condensing filler bytes");

		AddressRangeIterator addressRanges = undefinedSet.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			AddressRange addressRange = addressRanges.next();
			if (isRangeAllSameBytes(program, addressRange, (byte) 0xff, monitor)) {
				program.getListing()
						.createData(addressRange.getMinAddress(), alignmentDataType,
							(int) addressRange.getLength());
			}
		}

		//collapseFillerBytes( program, monitor );

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
		return "Condenses all filler bytes in a DEX/CDEX file";
	}

	@Override
	public String getName() {
		return "Android DEX/CDEX Condense Filler Bytes";
	}

	@Override
	public AnalysisPriority getPriority() {
		return new AnalysisPriority(Integer.MAX_VALUE);
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	private boolean isRangeAllSameBytes(Program program, AddressRange addressRange, byte value,
			TaskMonitor monitor) throws CancelledException {
		byte[] bytes = new byte[(int) addressRange.getLength()];
		try {
			program.getMemory().getBytes(addressRange.getMinAddress(), bytes);
		}
		catch (Exception e) {
			return false;
			//ignore
		}
		for (byte b : bytes) {
			monitor.checkCanceled();
			if (b != value) {
				return false;
			}
		}
		return true;
	}
}
