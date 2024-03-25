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
package wasm.analysis;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Float4DataType;
import ghidra.program.model.data.Float8DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.StackReference;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class WasmStackVariableAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Wasm Stack Analyzer";
	private static final String DESCRIPTION = "Creates C stack variables for Wasm functions.";

	public WasmStackVariableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.initialize(program.getFunctionManager().getFunctionCount());

		for (Function function : program.getListing().getFunctions(set, true)) {
			monitor.checkCancelled();
			monitor.setMessage("C Stack " + function.getName());
			monitor.incrementProgress(1);

			createStackPointerVariables(program, function, monitor);
		}

		return true;
	}

	private static DataType getMemoryDataType(String mnemonic) {
		switch (mnemonic) {
		case "i32.load":
		case "i32.store":
			return Undefined4DataType.dataType;
		case "i64.load":
		case "i64.store":
			return Undefined8DataType.dataType;
		case "f32.store":
		case "f32.load":
			return Float4DataType.dataType;
		case "f64.store":
		case "f64.load":
			return Float8DataType.dataType;
		case "i32.load8_s":
		case "i64.load8_s":
			return CharDataType.dataType;
		case "i32.load8_u":
		case "i64.load8_u":
			return ByteDataType.dataType;
		case "i32.store8":
		case "i64.store8":
			return Undefined1DataType.dataType;
		case "i32.load16_s":
		case "i64.load16_s":
			return ShortDataType.dataType;
		case "i32.load16_u":
		case "i64.load16_u":
			return UnsignedShortDataType.dataType;
		case "i32.store16":
		case "i64.store16":
			return Undefined2DataType.dataType;
		case "i64.load32_s":
			return IntegerDataType.dataType;
		case "i64.load32_u":
			return UnsignedIntegerDataType.dataType;
		case "i64.store32":
			return Undefined4DataType.dataType;
		case "v128.load":
		case "v128.store":
			return Undefined.getUndefinedDataType(16);
		case "v128.load8_lane":
		case "v128.load8_splat":
		case "v128.store8_lane":
			return Undefined1DataType.dataType;
		case "v128.load16_lane":
		case "v128.load16_splat":
		case "v128.store16_lane":
			return Undefined2DataType.dataType;
		case "v128.load32_lane":
		case "v128.load32_splat":
		case "v128.load32_zero":
		case "v128.store32_lane":
			return Undefined4DataType.dataType;
		case "v128.load64_lane":
		case "v128.load64_splat":
		case "v128.load64_zero":
		case "v128.store64_lane":
			return Undefined8DataType.dataType;
		case "v128.load8x8_s":
			return new ArrayDataType(SignedByteDataType.dataType, 8, 1);
		case "v128.load8x8_u":
			return new ArrayDataType(ByteDataType.dataType, 8, 1);
		case "v128.load16x4_s":
			return new ArrayDataType(ShortDataType.dataType, 4, 2);
		case "v128.load16x4_u":
			return new ArrayDataType(UnsignedShortDataType.dataType, 4, 2);
		case "v128.load32x2_s":
			return new ArrayDataType(IntegerDataType.dataType, 2, 4);
		case "v128.load32x2_u":
			return new ArrayDataType(UnsignedIntegerDataType.dataType, 2, 4);
		}
		return DefaultDataType.dataType;
	}

	private Variable createVar(Function func, int frameOffset, int offset, DataType dataType) throws InvalidInputException, DuplicateNameException {
		StackFrame frame = func.getStackFrame();
		int frameLoc = offset + frameOffset;
		Variable var = frame.getVariableContaining(frameLoc);
		if (var == null) {
			var = frame.createVariable(null, frameLoc, dataType, SourceType.ANALYSIS);
		} else if (var.getStackOffset() == frameLoc) {
			DataType oldDt = var.getDataType();
			if ((Undefined.isUndefined(oldDt) && !Undefined.isUndefined(dataType)) ||
			(oldDt == DefaultDataType.DEFAULT && dataType != DefaultDataType.DEFAULT)) {
				var.setDataType(dataType, SourceType.ANALYSIS);
			}
		}
		return var;
	}

	private void defineFuncVariable(Program program, Function func, Instruction instr, int opIndex, int stackOffset, RefType refType) throws InvalidInputException, DuplicateNameException {
		ReferenceManager refMgr = program.getReferenceManager();

		Reference ref = instr.getPrimaryReference(opIndex);
		DataType dataType = getMemoryDataType(instr.getMnemonicString());

		if (ref != null && ref instanceof StackReference)
			return;

		refMgr.addStackReference(instr.getMinAddress(), opIndex, stackOffset, refType, SourceType.ANALYSIS);
		createVar(func, 0, stackOffset, dataType);
	}

	// Get registers sorted by position within the register file
	private List<Register> getRegisters(Object[] collection) {
		List<Register> registers = new ArrayList<>();
		for (Object obj : collection) {
			if (obj instanceof Register) {
				registers.add((Register) obj);
			}
		}
		Collections.sort(registers);
		return registers;
	}

	private void createStackPointerVariables(Program program, Function func, TaskMonitor monitor) throws CancelledException {
		CallDepthChangeInfo info = new CallDepthChangeInfo(func, monitor);

		InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
		while (iter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = iter.next();

			try {
				String mnemonic = instr.getMnemonicString();
				if (mnemonic.contains(".load")) {
					// Note: inputObjects is not sorted in any particular order (it may be derived
					// from a HashSet)
					Register base = getRegisters(instr.getInputObjects()).get(0);
					// get offset from "align=A offset=O" operand
					Scalar offset = (Scalar) instr.getOpObjects(0)[1];
					int stackOffset = info.getRegDepth(instr.getMinAddress(), base);
					if (stackOffset == Function.INVALID_STACK_DEPTH_CHANGE) {
						continue;
					}
					defineFuncVariable(program, func, instr, 0, (int) (stackOffset + offset.getUnsignedValue()), RefType.READ);
				} else if (mnemonic.contains(".store")) {
					// Note: inputObjects is not sorted in any particular order (it may be derived
					// from a HashSet)
					Register base = getRegisters(instr.getInputObjects()).get(0);
					// get offset from "align=A offset=O" operand
					Scalar offset = (Scalar) instr.getOpObjects(0)[1];
					int stackOffset = info.getRegDepth(instr.getMinAddress(), base);
					if (stackOffset == Function.INVALID_STACK_DEPTH_CHANGE) {
						continue;
					}
					defineFuncVariable(program, func, instr, 0, (int) (stackOffset + offset.getUnsignedValue()), RefType.WRITE);
				} else if (mnemonic.equals("local.get") || mnemonic.equals("local.set")) {
					// These instructions will only have one input
					Register input = (Register) instr.getInputObjects()[0];
					int stackOffset = info.getRegDepth(instr.getMinAddress(), input);
					if (stackOffset == Function.INVALID_STACK_DEPTH_CHANGE) {
						continue;
					}
					if (stackOffset == info.getDepth(instr.getMinAddress()) || stackOffset == 0) {
						/*
						 * Heuristically, avoid simple references to the frame or stack base, as they're
						 * likely to be operands for a later operation
						 */
						continue;
					}
					defineFuncVariable(program, func, instr, 0, stackOffset, RefType.DATA);
				}
			} catch (Exception e) {
				Msg.warn(this, "Failed to process instruction at " + instr.getMinAddress() + ": " + instr + ": " + e.getMessage());
			}
		}
	}
}
