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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.pef.PefDebug;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PefLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class PefDebugAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "PEF Debug";
	private static final String DESCRIPTION = "Locates and applies PEF debug information.";

	public PefDebugAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(new AnalysisPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.priority() * 2));
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PefLoader.PEF_NAME.equals(program.getExecutableFormat());
	}

	@Override
	public boolean added(Program program, AddressSetView functionSet, TaskMonitor monitor,
			MessageLog log) {
		Listing listing = program.getListing();
		FunctionIterator functions = listing.getFunctions(functionSet, true);
		while (functions.hasNext() && !monitor.isCancelled()) {
			Function function = functions.next();
			Address address = function.getBody().getMaxAddress().add(1);
			if (isEnoughSpaceForDebugSymbol(program, address)) {
				try {
					applyStructure(program, address);
				}
				catch (Exception e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
			}
		}
		return true;
	}

	private void applyStructure(Program program, Address address) throws MemoryAccessException,
			AddressOutOfBoundsException, CodeUnitInsertionException, DataTypeConflictException,
			DuplicateNameException, InvalidInputException, CircularDependencyException {

		Listing listing = program.getListing();
		Memory memory = program.getMemory();

		PefDebug debug = new PefDebug(memory, address);
		if (!debug.isValid()) {
			return;
		}
		DataType debugDataType = debug.toDataType();
		DataUtilities.createData(program, address, debugDataType, debugDataType.getLength(), false,
			ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		Address functionAddress = address.subtract(debug.getDistance());
		Function function = listing.getFunctionAt(functionAddress);
		if (function != null) {
			function.setParentNamespace(getNamespace(program));
			function.setName(debug.getName(), SourceType.IMPORTED);
		}
		else {
			Msg.debug(this, "no function");
		}
	}

	private boolean isEnoughSpaceForDebugSymbol(Program program, Address startAddress) {
		Address endAddress = startAddress.add(PefDebug.SIZEOF);
		AddressSet addressSet = new AddressSet(startAddress, endAddress);
		InstructionIterator instructions = program.getListing().getInstructions(addressSet, true);
		return !instructions.hasNext();
	}

	private Namespace getNamespace(Program program) {
		Namespace namespace = program.getSymbolTable().getNamespace(".debug", null);
		if (namespace != null) {
			return namespace;
		}
		try {
			return program.getSymbolTable().createNameSpace(null, ".debug", SourceType.IMPORTED);
		}
		catch (Exception e) {
			return null;
		}

	}
}
