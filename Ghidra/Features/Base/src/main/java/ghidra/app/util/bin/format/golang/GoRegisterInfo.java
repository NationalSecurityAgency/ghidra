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
package ghidra.app.util.bin.format.golang;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.dwarf.DWARFUtil;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

/**
 * Immutable information about registers, alignment sizes, etc needed to allocate storage
 * for parameters during a function call.
 */
public class GoRegisterInfo {

	public enum RegType { INT, FLOAT }

	private final GoVerSet validVersions;
	private final List<Register> intRegisters;
	private final List<Register> floatRegisters;
	private final int stackInitialOffset;
	private final int maxAlign;	// 4 or 8
	private final Register currentGoroutineRegister;	// always points to g
	private final Register zeroRegister;	// always contains a zero value
	private final boolean zeroRegisterIsBuiltin;	// zero register is provided by cpu, or is manually set

	private final Register duffzeroDestParam;
	private final Register duffzeroZeroParam;	// if duffzero has 2nd param
	private final RegType duffzeroZeroParamType;

	private final Register closureContextRegister;

	GoRegisterInfo(List<Register> intRegisters, List<Register> floatRegisters,
			int stackInitialOffset, int maxAlign, Register currentGoroutineRegister,
			Register zeroRegister, boolean zeroRegisterIsBuiltin, Register duffzeroDestParam,
			Register duffzeroZeroParam, RegType duffzeroZeroParamType,
			Register closureContextRegister, GoVerSet validVersions) {
		this.validVersions = validVersions;
		this.intRegisters = intRegisters;
		this.floatRegisters = floatRegisters;
		this.stackInitialOffset = stackInitialOffset;
		this.maxAlign = maxAlign;
		this.currentGoroutineRegister = currentGoroutineRegister;
		this.zeroRegister = zeroRegister;
		this.zeroRegisterIsBuiltin = zeroRegisterIsBuiltin;

		this.duffzeroDestParam = duffzeroDestParam;
		this.duffzeroZeroParam = duffzeroZeroParam;
		this.duffzeroZeroParamType = duffzeroZeroParamType;

		this.closureContextRegister = closureContextRegister;
	}
	
	public GoVerSet getValidVersions() {
		return validVersions;
	}

	public int getIntRegisterSize() {
		return maxAlign; // TODO: HACK: ?????
	}

	public int getMaxAlign() {
		return maxAlign;
	}

	public Register getCurrentGoroutineRegister() {
		return currentGoroutineRegister;
	}

	public Register getZeroRegister() {
		return zeroRegister;
	}

	public boolean isZeroRegisterIsBuiltin() {
		return zeroRegisterIsBuiltin;
	}

	public List<Register> getIntRegisters() {
		return intRegisters;
	}

	public List<Register> getFloatRegisters() {
		return floatRegisters;
	}

	public int getStackInitialOffset() {
		return stackInitialOffset;
	}

	public boolean hasAbiInternalParamRegisters() {
		return !intRegisters.isEmpty() || !floatRegisters.isEmpty();
	}

	public List<Variable> getDuffzeroParams(Program program) {
		if (duffzeroDestParam == null) {
			return List.of();
		}
		try {
			ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
			DataType voidPtr = dtm.getPointer(VoidDataType.dataType);

			List<Variable> params = new ArrayList<>();

			params.add(new ParameterImpl("dest", Parameter.UNASSIGNED_ORDINAL, voidPtr,
				getStorageForReg(program, duffzeroDestParam, voidPtr.getLength()), true, program,
				SourceType.ANALYSIS));
			if (duffzeroZeroParam != null && duffzeroZeroParamType != null) {
				int regSize = duffzeroZeroParam.getMinimumByteSize();
				DataType dt = switch (duffzeroZeroParamType) {
					case FLOAT -> AbstractFloatDataType.getFloatDataType(regSize, dtm);
					case INT -> AbstractIntegerDataType.getUnsignedDataType(regSize, dtm);
				};
				params.add(new ParameterImpl("zeroValue", Parameter.UNASSIGNED_ORDINAL, dt,
					getStorageForReg(program, duffzeroZeroParam, regSize), true, program,
					SourceType.ANALYSIS));
			}

			return params;
		}
		catch (InvalidInputException e) {
			return List.of();
		}
	}

	public Register getClosureContextRegister() {
		return closureContextRegister;
	}

	private VariableStorage getStorageForReg(Program program, Register reg, int len)
			throws InvalidInputException {
		return new VariableStorage(program,
			DWARFUtil.convertRegisterListToVarnodeStorage(List.of(reg), len)
					.toArray(Varnode[]::new));
	}

	public int getAlignmentForType(DataType dt) {
		while (dt instanceof TypeDef || dt instanceof Array) {
			if (dt instanceof TypeDef td) {
				dt = td.getBaseDataType();
			}
			if (dt instanceof Array a) {
				dt = a.getDataType();
			}
		}
		if (isIntType(dt) && isIntrinsicSize(dt.getLength())) {
			return Math.min(maxAlign, dt.getLength());
		}
		if (dt instanceof Complex8DataType /* golang complex64 */ ) {
			return 4;
		}
		if (dt instanceof AbstractFloatDataType) {
			return Math.min(maxAlign, dt.getLength());
		}
		return maxAlign;
	}

	static boolean isIntType(DataType dt) {
		return dt instanceof AbstractIntegerDataType || dt instanceof WideCharDataType ||
			dt instanceof WideChar16DataType || dt instanceof WideChar32DataType ||
			dt instanceof Enum || dt instanceof BooleanDataType;
	}

	static boolean isIntrinsicSize(int size) {
		return Integer.bitCount(size) == 1;
	}
}
