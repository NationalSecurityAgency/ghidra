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
package ghidra.app.util.bin.format.dwarf;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.bin.format.dwarf.expression.*;
import ghidra.app.util.bin.format.dwarf.line.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves stack-relative register values without changing the program's listing.
 * Only bounded, straight-line instruction prefixes are evaluated. Whole-function
 * locations require an explicit DWARF prologue-end row; unknown values remain errors.
 */
class DWARFStackValueReader implements DWARFExpressionEvaluator.ValueReader {

	private static final long MAX_PREFIX_BYTES = 4096;
	private static final Map<DWARFCompilationUnit, NavigableSet<Long>> PROLOGUE_ENDS =
		new WeakHashMap<>();
	private final DWARFFunction function;
	private final long lexicalOffset;
	private final boolean wildcard;
	private Address pc;
	private SymbolicPropogator propagator;
	private boolean initialized;

	DWARFStackValueReader(DWARFFunction function, long lexicalOffset, boolean wildcard) {
		this.function = function;
		this.lexicalOffset = lexicalOffset;
		this.wildcard = wildcard;
	}

	private Address getLocation() throws IOException {
		Address location = function.address.add(lexicalOffset);
		if (wildcard) {
			location = null;
			DWARFCompilationUnit cu = function.diea.getCompilationUnit();
			NavigableSet<Long> ends = getPrologueEnds(cu);
			Long end = ends.ceiling(function.getEntryPc());
			if (end != null) {
				Address candidate = function.getProgram().getCodeAddress(end);
				if (function.getBody().contains(candidate)) {
					location = candidate;
				}
			}
		}
		return location;
	}

	boolean isFrameBaseValid(DWARFLocation location) throws DWARFExpressionValueException {
		try {
			Address selected = getLocation();
			return selected != null && location.contains(function.getEntryPc() +
				selected.subtract(function.address));
		}
		catch (IOException e) {
			DWARFExpressionValueException failure = new DWARFExpressionValueException(null);
			failure.initCause(e);
			throw failure;
		}
	}

	private static synchronized NavigableSet<Long> getPrologueEnds(DWARFCompilationUnit cu)
			throws IOException {
		NavigableSet<Long> result = PROLOGUE_ENDS.get(cu);
		if (result != null) {
			return result;
		}
		result = new TreeSet<>(Long::compareUnsigned);
		DWARFLine line = cu.getLine();
		if (line != null) {
			try (DWARFLineProgramExecutor rows = line.getLineProgramExecutor(cu)) {
				DWARFLineProgramState row;
				while ((row = rows.nextRow()) != null) {
					if (row.prologueEnd && !row.isEndSequence) {
						result.add(row.address);
					}
				}
			}
		}
		PROLOGUE_ENDS.put(cu, result);
		return result;
	}

	@Override
	public Object getValue(Varnode vn) throws DWARFExpressionValueException {
		try {
			initialize();
		}
		catch (IOException e) {
			DWARFExpressionValueException failure = new DWARFExpressionValueException(vn);
			failure.initCause(e);
			throw failure;
		}
		Program program = function.getProgram().getGhidraProgram();
		Register register = vn.isRegister() ? program.getRegister(vn.getAddress(), vn.getSize()) : null;
		if (propagator != null && register != null) {
			SymbolicPropogator.Value value = propagator.getRegisterValue(pc, register);
			Register sp = program.getCompilerSpec().getStackPointer();
			if (value != null && sp.equals(value.getRelativeRegister())) {
				return new Varnode(program.getCompilerSpec().getStackSpace().getAddress(value.getValue()), 0);
			}
		}
		throw new DWARFExpressionValueException(vn);
	}

	private void initialize() throws IOException {
		if (initialized) {
			return;
		}
		initialized = true;
		pc = getLocation();
		if (pc == null || !function.address.getAddressSpace().equals(pc.getAddressSpace()) ||
			!function.getBody().contains(pc) ||
			pc.subtract(function.address) < 0 || pc.subtract(function.address) > MAX_PREFIX_BYTES) {
			return;
		}
		Program program = function.getProgram().getGhidraProgram();
		Register sp = program.getCompilerSpec().getStackPointer();
		if (sp == null) {
			return;
		}
		PseudoDisassembler disassembler = new PseudoDisassembler(program);
		SymbolicPropogator candidate = new SymbolicPropogator(program, true) {
			@Override
			public Instruction getInstructionAt(Address address) {
				try {
					return disassembler.disassemble(address);
				}
				catch (InsufficientBytesException | UnknownInstructionException | UnknownContextException e) {
					return null;
				}
			}
		};
		// Reject control flow in the prefix rather than assuming a unique stack depth.
		Address cursor = function.address;
		while (cursor.compareTo(pc) < 0) {
			Instruction instruction = candidate.getInstructionAt(cursor);
			if (instruction == null || !function.getBody().contains(instruction.getMaxAddress()) ||
				instruction.getFlowType().isJump() || instruction.getFlowType().isCall() ||
				instruction.getFlowType().isTerminal()) {
				return;
			}
			cursor = instruction.getMaxAddress().next();
			if (cursor == null) {
				return;
			}
		}
		if (!cursor.equals(pc)) {
			return;
		}
		candidate.setParamRefCheck(false);
		candidate.setReturnRefCheck(false);
		candidate.setStoredRefCheck(false);
		candidate.setRegister(function.address, sp);
		try {
			candidate.flowConstants(function.address, new AddressSet(function.address, pc),
				new ContextEvaluatorAdapter(), true, TaskMonitor.DUMMY);
			propagator = candidate;
		}
		catch (CancelledException e) {
			// TaskMonitor.DUMMY cannot cancel.
			throw new AssertionError(e);
		}
	}
}
