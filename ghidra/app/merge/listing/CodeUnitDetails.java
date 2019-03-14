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
package ghidra.app.merge.listing;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.DiffUtility;

/**
 * This is a class with static methods for obtaining information about a code unit and its 
 * references. The information is provided as a String.
 */
public abstract class CodeUnitDetails {

	private static final String NEW_LINE = "\n";
	private static final String INDENT1 = "    ";

	/**
	 * Gets a string that indicates the code unit along with its overrides and its "from" references.
	 * This can contain new line characters.
	 * @param cu the code unit
	 * @return info about the code unit and its references.
	 */
	public static String getInstructionDetails(CodeUnit cu) {
		if (cu == null || !(cu instanceof Instruction)) {
			return "You must be on an instruction to see the details.";
		}
		return getCodeUnitDetails(cu) + getReferenceDetails(cu);
	}

	/**
	 * Gets a string that indicates the code unit along with its overrides.
	 * This can contain new line characters.
	 * @param cu the code unit
	 * @return info about the code unit.
	 */
	public static String getCodeUnitDetails(CodeUnit cu) {
		if (cu == null) {
			return "You must be on a code unit to see the details.";
		}
		String indent = INDENT1;
		StringBuffer buf = new StringBuffer();
		buf.append("Code Unit:" + NEW_LINE);
		Address min = cu.getMinAddress();
		Address max = cu.getMaxAddress();
		String addrRangeStr = min + ((min.equals(max)) ? "" : " - " + max);
		String cuRep;
		if (cu instanceof Data) {
			cuRep = ((Data) cu).getDataType().getPathName();
		}
		else if (cu instanceof Instruction) {
			Instruction inst = (Instruction) cu;
			boolean removedFallThrough =
				inst.isFallThroughOverridden() && (inst.getFallThrough() == null);
			boolean hasFlowOverride = inst.getFlowOverride() != FlowOverride.NONE;
			cuRep = cu.toString();
			if (removedFallThrough) {
				cuRep +=
					NEW_LINE + indent + getSpaces(addrRangeStr.length()) + "    " +
						"Removed FallThrough";
			}
			else if (inst.isFallThroughOverridden()) {
				Reference[] refs = cu.getReferencesFrom();
				// Show the fallthrough override.
				for (int i = 0; i < refs.length; i++) {
					if (refs[i].getReferenceType().isFallthrough()) {
						cuRep +=
							NEW_LINE + indent + getSpaces(addrRangeStr.length()) + "    " +
								"FallThrough Override: " +
								DiffUtility.getUserToAddressString(inst.getProgram(), refs[i]);
					}
				}
			}
			if (hasFlowOverride) {
				cuRep +=
					NEW_LINE + indent + getSpaces(addrRangeStr.length()) + "    " +
						"Flow Override: " + inst.getFlowOverride();
			}
			// Commented the following out, since we may want the hash code in the future.
//			cuRep +=
//				STANDARD_NEW_LINE + indent + getSpaces(addrRangeStr.length()) + "    " +
//					"Instruction Prototype hash = " +
//					Integer.toHexString(inst.getPrototype().hashCode());
		}
		else {
			cuRep = cu.toString();
		}
		buf.append(indent + addrRangeStr + "    " + cuRep + NEW_LINE);
		return buf.toString();
	}

	/**
	 * Gets a string that indicates the references from a code unit.
	 * This can contain new line characters.
	 * <br>Note: Data currently only indicates references on the minimum address.
	 * @param cu the code unit
	 * @return info about the code unit's references.
	 */
	public static String getReferenceDetails(CodeUnit cu) {
		if (cu == null) {
			return "You must be on a code unit to see the details.";
		}
		StringBuffer buf = new StringBuffer();
		buf.append("References: " + NEW_LINE);
		buf.append(getProgramRefDetails(cu.getProgram(), cu.getReferencesFrom()));
		return buf.toString();
	}

	private static String getRefInfo(Program pgm, Reference ref) {
		String typeStr = "Type: " + ref.getReferenceType();
		String fromStr = "  From: " + ref.getFromAddress();
		String operandStr =
			((ref.isMnemonicReference()) ? "  Mnemonic" : ("  Operand: " + ref.getOperandIndex()));
		String toStr = "  To: " + DiffUtility.getUserToAddressString(pgm, ref);
		String sourceStr = "  " + ref.getSource().toString();
		String primaryStr = ((ref.isPrimary()) ? "  Primary" : "");
		String symbolStr = "";
		long symbolID = ref.getSymbolID();
		if (symbolID != -1) {
			Symbol sym = pgm.getSymbolTable().getSymbol(symbolID);
			if (sym != null) {
				symbolStr = "  Symbol: " + sym.getName(true);
			}
		}
		return typeStr + fromStr + operandStr + toStr + sourceStr + primaryStr + symbolStr;
	}

	private static String getProgramRefDetails(Program pgm, Reference[] refs) {
		String indent = INDENT1;
		if (refs.length == 0) {
			return indent + "None";
		}
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < refs.length; i++) {
			if (refs[i].isExternalReference()) {
				buf.append(indent + "External Reference " + getRefInfo(pgm, refs[i]) + NEW_LINE);
			}
			else if (refs[i].isStackReference()) {
				buf.append(indent + "Stack Reference " + getRefInfo(pgm, refs[i]) + NEW_LINE);
			}
			else {
				buf.append(indent + "Reference " + getRefInfo(pgm, refs[i]) + NEW_LINE);
			}
		}
		return buf.toString();
	}

	private static String getSpaces(int numSpaces) {
		if (numSpaces <= 0) {
			return "";
		}
		StringBuffer buf = new StringBuffer(numSpaces);
		for (int i = 0; i < numSpaces; i++) {
			buf.append(" ");
		}
		return buf.toString();
	}

}
