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
package ghidra.test.processors;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.processors.support.EmulatorTestRunner;
import ghidra.test.processors.support.PCodeTestControlBlock;
import ghidra.test.processors.support.ProcessorEmulatorTestAdapter;
import ghidra.util.task.TaskMonitor;

public abstract class WasmEmulatorTestAdapter extends ProcessorEmulatorTestAdapter {

	private static final String[] REG_DUMP_SET = new String[] {};
	private static final byte[] MAIN_CONTROL_BLOCK_MAGIC = "AbCdEFgH".getBytes();
	private static final byte[] GROUP_CONTROL_BLOCK_MAGIC = "aBcDefGh".getBytes();

	public WasmEmulatorTestAdapter(String name, String languageID, String compilerSpecID) throws Exception {
		super(name, languageID, compilerSpecID, REG_DUMP_SET);
		setIgnoredBlocks(".module");
	}

	private static int getStructureComponent(Structure testInfoStruct, String fieldName) {
		for (DataTypeComponent component : testInfoStruct.getDefinedComponents()) {
			if (fieldName.equals(component.getFieldName())) {
				return component.getOffset();
			}
		}
		throw new RuntimeException(fieldName + " field not found within " +
				testInfoStruct.getName() + " structure definition");
	}

	private Address findBytes(Memory memory, Address startAddr, Address endAddr, byte[] bytes) throws Exception {
		return memory.findBytes(startAddr, endAddr, bytes, null, true, TaskMonitor.DUMMY);
	}

	private Address readPointer(Program program, Address address) throws Exception {
		int pointerSize = program.getDefaultPointerSize();
		long offset = pointerSize == 4 ? (long) program.getMemory().getInt(address)
				: program.getMemory().getLong(address);
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private void writePointer(Program program, Address address, Address target) throws Exception {
		int pointerSize = program.getDefaultPointerSize();
		if (pointerSize == 4) {
			program.getMemory().setInt(address, (int) target.getOffset());
		} else {
			program.getMemory().setLong(address, target.getOffset());
		}
	}

	private void mungeFuncPointer(Program program, Address address) throws Exception {
		long index = readPointer(program, address).getOffset();
		Address tableAddress = program.getAddressFactory().getAddressSpace("table")
				.getAddress(index * program.getDefaultPointerSize());
		Address funcAddress = readPointer(program, tableAddress);
		writePointer(program, address, funcAddress);
	}

	private void mungeFuncTable(Program program, Address tableAddress, int funcOffset, int funcSize) throws Exception {
		while (true) {
			Address functionAddress = readPointer(program, tableAddress.add(funcOffset));
			if (functionAddress.getOffset() == 0)
				break;
			mungeFuncPointer(program, tableAddress.add(funcOffset));
			tableAddress = tableAddress.add(funcSize);
		}
	}

	@Override
	protected void postImport(Program program) throws Exception {
		/*
		 * munge in-memory function pointer addresses so they point to the actual code.
		 * The better way to handle this would be to override readCodePointer...
		 */
		Memory memory = program.getMemory();
		MemoryBlock memory0 = memory.getBlock(".memory0");
		Structure functionInfoStruct = (Structure) testInfoStruct.getDataTypeManager().getDataType(CategoryPath.ROOT,
				"FunctionInfo");
		int mainArrayOffset = getStructureComponent(testInfoStruct, "funcInfoArrayPtr");
		int groupArrayOffset = getStructureComponent(groupInfoStruct, "funcInfoArrayPtr");
		int funcOffset = getStructureComponent(functionInfoStruct, "func");
		int funcSize = functionInfoStruct.getLength();

		Address mainControlBlock = findBytes(memory, memory0.getStart(), memory0.getEnd(), MAIN_CONTROL_BLOCK_MAGIC);
		mungeFuncPointer(program, mainControlBlock.add(getStructureComponent(testInfoStruct, "onPass")));
		mungeFuncPointer(program, mainControlBlock.add(getStructureComponent(testInfoStruct, "onError")));
		mungeFuncPointer(program, mainControlBlock.add(getStructureComponent(testInfoStruct, "onDone")));
		mungeFuncPointer(program, mainControlBlock.add(getStructureComponent(testInfoStruct, "sprintf5")));
		Address mainFuncTable = readPointer(program, mainControlBlock.add(mainArrayOffset));
		mungeFuncTable(program, mainFuncTable, funcOffset, funcSize);

		Address start = memory0.getStart();
		while (true) {
			Address groupControlBlock = findBytes(memory, start, memory0.getEnd(), GROUP_CONTROL_BLOCK_MAGIC);
			if (groupControlBlock == null) {
				break;
			}
			Address groupFuncTable = readPointer(program, groupControlBlock.add(groupArrayOffset));
			// XXX hack: we can't munge the whole table because they'll get called from assembly,
			// so only munge the first entry which points to the group Main and gets read by
			// PCodeTestGroupControlBlock. Only table indices  1 and above are used by the emulated
			// code, so this munge is safe (if hackish)
			mungeFuncPointer(program, groupFuncTable.add(funcOffset));
			start = groupControlBlock.add(GROUP_CONTROL_BLOCK_MAGIC.length);
		}

		/* Run analysis now so that all the code segments are properly defined */
		setAnalysisOptions(program.getOptions(Program.ANALYSIS_PROPERTIES));
		GhidraProgramUtilities.markProgramAnalyzed(program);
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		analysisMgr.cancelQueuedTasks(); // GhidraProject import utility jumped the gun with analysis initialization
		analysisMgr.initializeOptions();
		analysisMgr.reAnalyzeAll(null);
		analysisMgr.startAnalysis(TaskMonitor.DUMMY); // method blocks during analysis
	}

	@Override
	protected void analyze(Program program, PCodeTestControlBlock testControlBlock) throws Exception {
		/* Nothing: we ran analysis already */
	}

	@Override
	protected void initializeState(EmulatorTestRunner testRunner, Program program) throws Exception {
		super.initializeState(testRunner, program);
		MemoryBlock memory0 = program.getMemory().getBlock(".memory0");
		testRunner.setRegister("SP", memory0.getEnd().add(0x10000).getOffset());
	}
}
