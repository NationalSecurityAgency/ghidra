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
package ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin;

import ghidra.app.services.*;
import ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock;
import ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TEBAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Windows x86 Thread Environment Block (TEB) Analyzer";
	private static final String DESCRIPTION =
		"Create and mark up a Thread Environment Block. Set FS or GS segments to point to it.";

	protected static final String ADDRESS_OPTION_NAME = "Starting Address of the TEB";
	protected static final String ADDRESS_OPTION_DESCRIPTION =
		"Address in RAM where TEB is located (must not be mapped to another block)";
	protected static final String ADDRESS_OPTION_DEFAULT_VALUE = "";

	protected static final String VERSION_OPTION_NAME = "Windows OS Version";
	protected static final String VERSION_OPTION_DESCRIPTION =
		"Version of the TEB fields to lay down. Many common fields persist across multiple OS versions.";
	protected static final WinVersion VERSION_OPTION_DEFAULT_VALUE = WinVersion.WIN_7;

	protected String tebAddressString = ADDRESS_OPTION_DEFAULT_VALUE;
	protected WinVersion winVersion = VERSION_OPTION_DEFAULT_VALUE;

	public TEBAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getLanguageID().getIdAsString().startsWith("x86")) {
			return false;
		}
		return PEUtil.isVisualStudioOrClangPe(program);
	}

	private Address findBlockLocation(Program program, boolean is64Bit, int blockSize) {
		long offset = is64Bit ? 0xff00000000L : 0xffdff000L;
		Memory memory = program.getMemory();
		AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address startAddr = addrSpace.getAddress(offset);
		Address endAddr = startAddr.add(blockSize - 1);
		if (!memory.intersects(startAddr, endAddr)) {
			return startAddr;
		}
		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			Address addr = block.getEnd();
			if (addr.getAddressSpace() != addrSpace) {
				continue;
			}
			if (startAddr.compareTo(addr) < 0) {
				startAddr = addr;
			}
		}
		startAddr = startAddr.add(1);
		return startAddr;
	}

	private void setTEBAddress(Program program, ThreadEnvironmentBlock teb) {
		long offset;
		try {
			offset = Long.parseLong(tebAddressString, 16);
		}
		catch (NumberFormatException ex) {
			offset = 0;		// Option is empty or bad format
		}
		Address addr;
		if (offset == 0) {
			addr = findBlockLocation(program, teb.is64(), teb.getBlockSize());
		}
		else {
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		}
		teb.setAddress(addr);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		MemoryBlock block = program.getMemory().getBlock(ThreadEnvironmentBlock.BLOCK_NAME);
		if (block != null) {
			return true;
		}
		ThreadEnvironmentBlock teb = new ThreadEnvironmentBlock(program, winVersion);
		setTEBAddress(program, teb);
		boolean commit = true;
		int transactionID = program.startTransaction("Thread Environment Block");
		try {
			teb.createBlocksAndSymbols();
			teb.setRegisterValue();
		}
		catch (Exception e) {
			Msg.error(this, "Unable to create the Thread Environment Block");
			commit = false;
		}
		program.endTransaction(transactionID, commit);
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(ADDRESS_OPTION_NAME, tebAddressString, null,
			ADDRESS_OPTION_DESCRIPTION);
		options.registerOption(VERSION_OPTION_NAME, winVersion, null, VERSION_OPTION_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		tebAddressString = options.getString(ADDRESS_OPTION_NAME, tebAddressString);
		winVersion = options.getEnum(VERSION_OPTION_NAME, winVersion);
	}
}
