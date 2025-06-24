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

import java.util.*;

import ghidra.app.util.bin.format.dwarf.DWARFUtil;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.NumericUtilities;

/**
 * Logic and helper for allocating storage for a function's parameters and return value.
 * <p>
 * Not threadsafe.
 */
public class GoParamStorageAllocator {
	private static final int INTREG = 0;
	private static final int FLOATREG = 1;

	private List<List<Register>> regs;
	private int[] nextReg = new int[2];
	private GoRegisterInfo callspecInfo;
	private long stackOffset;
	private boolean isBigEndian;
	private String archDescription;

	/**
	 * Creates a new golang function call storage allocator for the specified Ghidra Language.
	 * <p>
	 * See {@link GoRegisterInfoManager#getRegisterInfoForLang(Language, GoVer)}
	 * 
	 * @param program {@link Program}
	 * @param goVersion version of go used to create the program
	 */
	public GoParamStorageAllocator(Program program, GoVer goVersion) {
		Language lang = program.getLanguage();

		this.callspecInfo =
			GoRegisterInfoManager.getInstance().getRegisterInfoForLang(lang, goVersion);
		this.stackOffset = callspecInfo.getStackInitialOffset();
		this.regs = List.of(callspecInfo.getIntRegisters(), callspecInfo.getFloatRegisters());
		this.isBigEndian = lang.isBigEndian();
		this.archDescription =
			"%s_%d".formatted(lang.getLanguageDescription().getProcessor().toString(),
				lang.getLanguageDescription().getSize());
	}

	private GoParamStorageAllocator(List<List<Register>> regs, int[] nextReg,
			GoRegisterInfo callspecInfo, long stackOffset, boolean isBigEndian,
			String archDescription) {
		this.regs = List.of(regs.get(INTREG), regs.get(FLOATREG));
		this.nextReg = new int[] { nextReg[INTREG], nextReg[FLOATREG] };
		this.callspecInfo = callspecInfo;
		this.stackOffset = stackOffset;
		this.isBigEndian = isBigEndian;
		this.archDescription = archDescription;
	}

	@Override
	public GoParamStorageAllocator clone() {
		return new GoParamStorageAllocator(regs, nextReg, callspecInfo, stackOffset, isBigEndian,
			archDescription);
	}

	public String getArchDescription() {
		return archDescription;
	}

	public boolean isBigEndian() {
		return isBigEndian;
	}

	public void resetRegAllocation() {
		nextReg[INTREG] = 0;
		nextReg[FLOATREG] = 0;
	}

	private boolean allocateReg(int count, int regType, DataType dt, List<Register> result) {
		int newNextReg = nextReg[regType] + count;
		if (newNextReg > regs.get(regType).size()) {
			return false;
		}

		int remainingSize = dt.getLength();
		for (int regNum = nextReg[regType]; regNum < newNextReg; regNum++) {
			Register reg = getBestFitRegister(regs.get(regType).get(regNum), remainingSize);
			remainingSize -= reg.getMinimumByteSize();
			result.add(reg);
		}
		nextReg[regType] = newNextReg;
		return true;
	}

	private Register getBestFitRegister(Register reg, int size) {
		while (reg.getMinimumByteSize() > size && reg.hasChildren()) {
			reg = reg.getChildRegisters().get(0);
		}
		return reg;
	}

	private int[] saveRegAllocation() {
		return new int[] { nextReg[INTREG], nextReg[FLOATREG] };
	}

	private void restoreRegAllocation(int[] savedNextReg) {
		nextReg[INTREG] = savedNextReg[INTREG];
		nextReg[FLOATREG] = savedNextReg[FLOATREG];
	}

	public void setAbi0Mode() {
		regs = List.of(List.of(), List.of());
	}

	public boolean isAbi0Mode() {
		return regs.get(INTREG).isEmpty() && regs.get(FLOATREG).isEmpty();
	}

	/**
	 * Returns the integer parameter that follows the supplied register.
	 * 
	 * @param reg register in the integer reg list
	 * @return the following register of the queried register, or null if no following register
	 * found
	 */
	public Register getNextIntParamRegister(Register reg) {
		List<Register> intRegs = regs.get(INTREG);
		for (int regNum = 0; regNum < intRegs.size() - 1; regNum++) {
			Register tmpReg = intRegs.get(regNum);
			if (tmpReg.equals(reg)) {
				return intRegs.get(regNum + 1);
			}
		}
		return null;
	}

	/**
	 * Returns a list of {@link Register registers} that will successfully store the specified
	 * data type, as well as marking those registers as used and unavailable.
	 * 
	 * @param dt {@link DataType} to allocate register space for
	 * @return list of {@link Register registers}, possibly empty if the data type was zero-length,
	 * possibly null if the data type is not compatible with register storage
	 */
	public List<Register> getRegistersFor(DataType dt) {
		return getRegistersFor(dt, true);
	}

	/**
	 * Returns a list of {@link Register registers} that will successfully store the specified
	 * data type, as well as marking those registers as used and unavailable.
	 * 
	 * @param dt {@link DataType} to allocate register space for
	 * @param allowEndianFixups boolean flag, if true the result (if it contains more than a single
	 * location) will automatically be adjusted in little endian programs to match how storage
	 * varnodes are laid-out, if false the result will not be adjusted 
	 * @return list of {@link Register registers}, possibly empty if the data type was zero-length,
	 * possibly null if the data type is not compatible with register storage
	 */
	public List<Register> getRegistersFor(DataType dt, boolean allowEndianFixups) {
		int[] saveRegAllocation = saveRegAllocation();
		List<Register> result = new ArrayList<>();

		if (!countRegistersFor(dt, result)) {
			restoreRegAllocation(saveRegAllocation);
			return null;
		}
		
		if (allowEndianFixups && !isBigEndian && result.size() > 1) {
			Collections.reverse(result);
		}

		return new ArrayList<>(result);
	}

	/**
	 * Returns the stack offset that should be used to store the data type on the stack, as well
	 * as marking that stack area as used and unavailable.
	 * 
	 * @param dt {@link DataType} to allocate stack space for
	 * @return offset in stack where the data item will be located
	 */
	public long getStackAllocation(DataType dt) {
		if (dt.isZeroLength()) {
			return stackOffset;
		}
		alignStackFor(dt);
		long result = stackOffset;
		stackOffset += dt.getLength();
		return result;
	}

	public long getStackOffset() {
		return stackOffset;
	}

	public void setStackOffset(long newStackOffset) {
		this.stackOffset = newStackOffset;
	}

	public void alignStackFor(DataType dt) {
		int alignmentSize = callspecInfo.getAlignmentForType(dt);
		stackOffset = NumericUtilities.getUnsignedAlignedValue(stackOffset, alignmentSize);
	}

	public void alignStack() {
		stackOffset =
			NumericUtilities.getUnsignedAlignedValue(stackOffset, callspecInfo.getMaxAlign());
	}

	public Register getClosureContextRegister() {
		return callspecInfo.getClosureContextRegister();
	}

	private boolean countRegistersFor(DataType dt, List<Register> result) {
		if (DWARFUtil.isZeroByteDataType(dt)) {
			return false;
		}

		if (dt instanceof TypeDef typedefDT) {
			dt = typedefDT.getBaseDataType();
		}
		if (dt instanceof Pointer) {
			return allocateReg(1, INTREG, dt, result);
		}
		if (GoRegisterInfo.isIntType(dt)) {
			int size = dt.getLength();
			int intRegSize = callspecInfo.getIntRegisterSize();
			if (size <= intRegSize * 2) {
				return allocateReg(
					(int) (NumericUtilities.getUnsignedAlignedValue(size, intRegSize) / intRegSize),
					INTREG, dt, result);
			}
		}
		if (dt instanceof AbstractFloatDataType) {
			return allocateReg(1, FLOATREG, dt, result);
		}
		if (dt instanceof Array array) {
			int numElements = array.getNumElements();
			if (numElements == 0) {
				return true;
			}
			if (numElements == 1 && countRegistersFor(array.getDataType(), result)) {
				return true;
			}
			return false;
		}
		if (dt instanceof Structure struct) {
//			DataTypeComponent prevDTC = null;
			for (DataTypeComponent dtc : struct.getDefinedComponents()) {
//				int padding = prevDTC != null ? dtc.getOffset() - prevDTC.getOffset() : 0;
//				if (padding != 0) {
//
//				}
				if (!countRegistersFor(dtc.getDataType(), result)) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
}
