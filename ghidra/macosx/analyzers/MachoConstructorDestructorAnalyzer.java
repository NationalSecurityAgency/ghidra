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
package ghidra.macosx.analyzers;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class MachoConstructorDestructorAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Mach-O Constructor/Destructor";
	private static final String DESCRIPTION =
		"Creates pointers to global constructors and destructors in a Mach-O file.";

	private static final String CONSTRUCTOR = "__constructor";
	private static final String DESTRUCTOR = "__destructor";

	public MachoConstructorDestructorAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		List<MemoryBlock> blocks = getBlocks(program);

		for (MemoryBlock block : blocks) {

			Address currentAddress = block.getStart();

			while (!monitor.isCancelled()) {
				if (currentAddress.compareTo(block.getEnd()) >= 0) {
					break;
				}
				try {
					Data data =
						program.getListing().createData(currentAddress, new PointerDataType());
					currentAddress = currentAddress.add(data.getLength());
				}
				catch (CodeUnitInsertionException e) {
					break;
				}
				catch (DataTypeConflictException e) {
					break;
				}
			}
		}

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return checkIfValid(program);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return checkIfValid(program);
	}

	private boolean checkIfValid(Program program) {
		return !getBlocks(program).isEmpty();
	}

	private List<MemoryBlock> getBlocks(Program program) {
		List<MemoryBlock> list = new ArrayList<MemoryBlock>();
		if (program.getExecutableFormat().equals(MachoLoader.MACH_O_NAME)) {
			MemoryBlock[] blocks = program.getMemory().getBlocks();
			for (MemoryBlock block : blocks) {
				if (block.getName().equals(CONSTRUCTOR)) {
					list.add(block);
				}
				else if (block.getName().equals(DESTRUCTOR)) {
					list.add(block);
				}
			}
		}
		return list;
	}
}
