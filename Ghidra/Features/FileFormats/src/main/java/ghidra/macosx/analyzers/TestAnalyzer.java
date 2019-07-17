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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TestAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Test";
	private static final String DESCRIPTION = "This is a test analyzer.";

	private static final String UNWIND_INFO = "__unwind_info";

	public TestAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setPrototype();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		DataType dataType = getDataType();

		MemoryBlock block = program.getMemory().getBlock(UNWIND_INFO);

		Address currentAddress = block.getStart();

		while (!monitor.isCancelled()) {

			Address intermediateEndAddress = currentAddress.add(dataType.getLength());

			if (intermediateEndAddress.compareTo(block.getEnd()) > 0) {
				break;
			}

			try {
				Data data = program.getListing().createData(currentAddress, dataType);

				if (data.getLength() != dataType.getLength()) {
					//don't need to check this..
				}

				program.getListing().setComment(currentAddress, CodeUnit.PLATE_COMMENT,
					"Address = " + currentAddress.toString());
				currentAddress = currentAddress.add(data.getLength());

			}
			catch (CodeUnitInsertionException e) {
				log.appendException(e);
				return false;
			}
			catch (DataTypeConflictException e) {
				log.appendException(e);
				return false;
			}
		}

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return checkIfMacho(program);
	}

	private boolean checkIfMacho(Program program) {
//		if ( !SystemUtilities.isInDevelopmentMode() ) {//this check is ONLY for this test analyzer, so it won't appear in RUNTIME environment
//			return false;
//		}
//		if ( program.getExecutableFormat().equals( MachoLoader.MACH_O_NAME ) ) {
//			MemoryBlock [] blocks = program.getMemory().getBlocks();
//			for ( MemoryBlock block : blocks ) {
//				if ( block.getName().equals( UNWIND_INFO ) ) {
//					return true;
//				}
//			}
//		}
		return false;
	}

	private DataType getDataType() {
		Structure structure = new StructureDataType("unwindStruct", 0);
		structure.add(new FloatDataType(), "a", "this is a float");
		structure.add(new DWordDataType(), "b", "this is a dword");
		structure.add(new DoubleDataType(), "c", "this is a double");
		return structure;
	}
}
