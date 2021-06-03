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
package ghidra.program.util;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.StringUtilities;

public class InstructionUtils {

	/**
	 * Get details instruction info as formatted text
	 * @param instruction
	 * @param debug SleighDebugerLogger for specified instruction or null 
	 * @return instruction details
	 */
	public static String getFormattedInstructionDetails(Instruction instruction,
			SleighDebugLogger debug) {
		if (instruction == null) {
			return null;
		}

		StringBuffer textBuf = new StringBuffer("Instruction Summary");
		textBuf.append("\n-------------------");
		textBuf.append("\nMnemonic          : " + instruction.getMnemonicString());
		textBuf.append("\nNumber of Operands: " + instruction.getNumOperands());
		textBuf.append("\nAddress           : " + instruction.getMinAddress().toString(true));
		FlowType flowType = instruction.getFlowType();
		textBuf.append("\nFlow Type         : " + flowType.toString());
		FlowOverride flowOverride = instruction.getFlowOverride();
		if (flowOverride != FlowOverride.NONE &&
			instruction.getPrototype().getFlowType(instruction.getInstructionContext()) != flowType) {
			textBuf.append("\n  >>> reflects " + flowOverride + " flow override");
		}
		Address fallAddr = instruction.getFallThrough();
		textBuf.append("\nFallthrough       : " + (fallAddr != null ? fallAddr : "<none>"));
		if (instruction.isFallThroughOverridden()) {
			textBuf.append("\n  >>> reflects fallthrough override");
		}
		textBuf.append("\nDelay slot depth  : " + instruction.getDelaySlotDepth() +
			(instruction.isInDelaySlot() ? " in slot" : ""));
		textBuf.append(
			"\nHash              : " + Integer.toHexString(instruction.getPrototype().hashCode())).append(
			'\n');

		textBuf.append("\nInput Objects:\n" +
			getString(getFormatedInstructionObjects(instruction, true), true));
		textBuf.append("\nResult Objects:\n" +
			getString(getFormatedInstructionObjects(instruction, false), true));
		textBuf.append(
			"\nConstructor Line #'s:\n" + getString(debug.getConstructorLineNumbers(), true)).append(
			'\n');
		textBuf.append("\nByte Length : " + instruction.getLength());
		try {
			textBuf.append("\nInstr Bytes : " +
				SleighDebugLogger.getFormattedBytes(instruction.getBytes()));
			textBuf.append("\nMask        : " + debug.getFormattedInstructionMask(-1));
			textBuf.append("\nMasked Bytes: " + debug.getFormattedMaskedValue(-1)).append('\n');
		}
		catch (MemoryAccessException e) {
			// ignore
		}
		textBuf.append("\nInstr Context:\n");
		textBuf.append(getFormattedContextRegisterValueBreakout(instruction, "   "));

		return textBuf.toString();
	}

	/**
	 * Get formatted context register as list of child register values
	 * @param instr
	 * @return formatted context data
	 */
	public static String getFormattedContextRegisterValueBreakout(Instruction instr, String indent) {
		ProgramContext programContext = instr.getProgram().getProgramContext();
		Register contextReg = programContext.getBaseContextRegister();
		if (contextReg == null) {
			return indent + "[Instruction context not defined]";
		}
		return getFormattedRegisterValueBits(instr.getRegisterValue(contextReg), indent);
	}

	private static Comparator<String> OBJSTRING_COMPARATOR = new Comparator<String>() {
		@Override
		public int compare(String o1, String o2) {
			// registers first (they do not have colons)
			boolean isRegister1 = o1.indexOf(':') < 0;
			boolean isRegister2 = o2.indexOf(':') < 0;
			if (isRegister1 != isRegister2) {
				return isRegister1 ? -1 : 1;
			}
			return o1.compareTo(o2);
		}
	};

	/**
	 * Format instruction input or result objects
	 * @param instr instruction
	 * @param input input objects if true else result objects
	 * @return formatted array of strings
	 */
	public static String[] getFormatedInstructionObjects(Instruction instr, boolean input) {
		Object[] objs = input ? instr.getInputObjects() : instr.getResultObjects();
		return getFormatedInstructionObjects(objs);
	}

	/**
	 * Format instruction operand objects
	 * @param instr instruction
	 * @param opIndex the operand index
	 * @return formatted array of strings
	 */
	public static String[] getFormatedOperandObjects(Instruction instr, int opIndex) {
		Object[] objs = instr.getOpObjects(opIndex);
		return getFormatedInstructionObjects(objs);
	}

	private static String[] getFormatedInstructionObjects(Object[] objs) {
		if (objs == null) {
			return null;
		}
		HashSet<String> set = new HashSet<String>();
		for (Object element : objs) {
			if (element instanceof Scalar) {
				Scalar scalar = (Scalar) element;
				set.add("const:" + scalar.toString());
			}
			else if (element instanceof Register) {
				Register reg = (Register) element;
				set.add(reg.toString());
			}
			else if (element instanceof Address) {
				Address addr = (Address) element;
				set.add(addr.toString(true));
			}
		}
		String[] list = new String[set.size()];
		set.toArray(list);
		Arrays.sort(list, OBJSTRING_COMPARATOR);
		return list;
	}

	/**
	 * Get formatted RegisterValue as list of child register values
	 * @param value
	 * @return
	 */
	public static String getFormattedRegisterValueBits(RegisterValue value, String indent) {
		if (value == null || value.getValueMask().equals(BigInteger.ZERO)) {
			return indent + "[Instruction context has not been set]";
		}
		Register baseReg = value.getRegister();
		if (!baseReg.hasChildren()) {
			return indent + baseReg.getName() + " == 0x" +
				value.getUnsignedValueIgnoreMask().toString(16);
		}
		StringBuilder buf = new StringBuilder();
		int baseRegSize = baseReg.getMinimumByteSize() * 8;
		int paddedLen = 0;
		for (Register reg : baseReg.getChildRegisters()) {
			int len = reg.getName().length();
			if (len > paddedLen) {
				paddedLen = len;
			}
		}
		for (Register reg : baseReg.getChildRegisters()) {
			RegisterValue childActualValue = value.getRegisterValue(reg);
			if (childActualValue.hasAnyValue()) {
				int pad = paddedLen - reg.getName().length();
				BigInteger actual = childActualValue.getUnsignedValueIgnoreMask();
				int msb = baseRegSize - reg.getLeastSignificatBitInBaseRegister() - 1;
				int lsb = msb - reg.getBitLength() + 1;
				if (buf.length() != 0) {
					buf.append("\n");
				}
				buf.append(indent);
				String lsbStr = StringUtilities.pad(Integer.toString(lsb), '0', 2);
				String msbStr = StringUtilities.pad(Integer.toString(msb), '0', 2);
				String leftStr = reg.getName() + "(" + lsbStr + "," + msbStr + ")";
				leftStr = StringUtilities.pad(leftStr, ' ', -leftStr.length() - pad);
				buf.append(leftStr + " == 0x" + actual.toString(16));
			}
		}
		return buf.toString();
	}

	private static String getString(String strs[], boolean multiline) {
		if (multiline) {
			List<String> list = Arrays.asList(strs);
			return getString(list, true);
		}
		if (strs == null) {
			return "-none-";
		}
		StringBuffer outStr = new StringBuffer();
		for (String str : strs) {
			if (outStr.length() != 0) {
				outStr.append(", ");
			}
			outStr.append(str.toString());
		}
		return outStr.toString();
	}

	private static String getString(List<String> list, boolean multiline) {
		if (!multiline) {
			String[] strs = list != null ? new String[list.size()] : null;
			return getString(strs, false);
		}
		StringBuffer strBuf = new StringBuffer("   ");
		if (list == null) {
			strBuf.append("-none-");
			return strBuf.toString();
		}
		int linelen = 0;
		for (String str : list) {
			if (linelen != 0) {
				strBuf.append(", ");
				linelen += 2;
			}
			if (linelen >= 40) {
				strBuf.append("\n   ");
				linelen = 0;
			}
			linelen += str.length();
			strBuf.append(str);
		}
		return strBuf.toString();
	}
}
