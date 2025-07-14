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
package ghidra.app.util.bin.format.dwarf.macro.entry;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.attribs.*;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroOpcode;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroOpcode.Def;

/**
 * Represents a generic macro info entry, and can contain any macro entry element.
 * <p>
 * Specific macro entry classes are derived from this and provide getters to ease fetching
 * values that are expected for that class.  These classes are expected to implement a copy-ctor
 * that accepts a DWARFMacroInfoEntry containing the raw data to be wrapped, and must be registered
 * in {@link #toSpecializedForm(DWARFMacroInfoEntry)} method's switch() statement.
 */
public class DWARFMacroInfoEntry {

	/**
	 * Reads a DWARF macro info entry from the stream.
	 * 
	 * @param reader {@link BinaryReader} stream
	 * @param macroHeader the parent {@link DWARFMacroHeader}
	 * @return a {@link DWARFMacroInfoEntry}, or subclass if element is a known opcode, or 
	 * {@code null} if the element was the end-of-list marker 
	 * @throws IOException if error reading or unknown opcode
	 */
	public static DWARFMacroInfoEntry read(BinaryReader reader, DWARFMacroHeader macroHeader)
			throws IOException {

		Map<Integer, List<DWARFForm>> opcodeMap = macroHeader.getOpcodeMap();

		long startOffset = reader.getPointerIndex();
		int rawOpcode = reader.readNextUnsignedByte();
		DWARFMacroOpcode opcode = DWARFMacroOpcode.of(rawOpcode);
		List<DWARFForm> operandForms = opcodeMap.get(rawOpcode);
		if (operandForms == null) {
			throw new IOException("Unknown DW_MACRO opcode %x at position %d [0x%x]"
					.formatted(rawOpcode, startOffset, startOffset));
		}

		DWARFAttributeValue[] operandValues = new DWARFAttributeValue[operandForms.size()];
		for (int i = 0; i < operandForms.size(); i++) {
			DWARFForm form = operandForms.get(i);
			Def opcodeDef = new DWARFMacroOpcode.Def(opcode, rawOpcode, form);
			DWARFFormContext readContext = new DWARFFormContext(reader,
				macroHeader.getCompilationUnit(), opcodeDef, macroHeader.getIntSize());
			operandValues[i] = form.readValue(readContext);
		}
		DWARFMacroInfoEntry genericEntry =
			new DWARFMacroInfoEntry(opcode, rawOpcode, operandValues, macroHeader);

		return toSpecializedForm(genericEntry);
	}

	public static DWARFMacroInfoEntry toSpecializedForm(DWARFMacroInfoEntry genericEntry) {
		return switch (genericEntry.getOpcode()) {
			case MACRO_UNIT_TERMINATOR -> null;
			case DW_MACRO_define, DW_MACRO_define_strp, DW_MACRO_define_sup, DW_MACRO_define_strx -> new DWARFMacroDefine(
				genericEntry);
			case DW_MACRO_undef, DW_MACRO_undef_strp, DW_MACRO_undef_sup, DW_MACRO_undef_strx -> new DWARFMacroUndef(
				genericEntry);
			case DW_MACRO_start_file -> new DWARFMacroStartFile(genericEntry);
			case DW_MACRO_end_file -> new DWARFMacroEndFile(genericEntry);
			case DW_MACRO_import, DW_MACRO_import_sup -> new DWARFMacroImport(genericEntry);
			default -> genericEntry;
		};
	}

	protected DWARFMacroOpcode opcode;
	protected int rawOpcode;
	protected DWARFAttributeValue[] operandValues;
	protected DWARFMacroHeader macroHeader;

	protected DWARFMacroInfoEntry(DWARFMacroOpcode opcode, DWARFMacroHeader macroHeader) {
		this.opcode = opcode;
		this.rawOpcode = opcode.getRawOpcode();
		this.macroHeader = macroHeader;
		this.operandValues = new DWARFAttributeValue[opcode.getOperandForms().length];
	}

	public DWARFMacroInfoEntry(DWARFMacroOpcode opcode, int rawOpcode,
			DWARFAttributeValue[] operandValues, DWARFMacroHeader macroHeader) {
		this.opcode = opcode;
		this.rawOpcode = rawOpcode;
		this.operandValues = operandValues;
		this.macroHeader = macroHeader;
	}

	protected DWARFMacroInfoEntry(DWARFMacroInfoEntry other) {
		this.opcode = other.opcode;
		this.rawOpcode = other.rawOpcode;
		this.operandValues = other.operandValues;
		this.macroHeader = other.macroHeader;
	}

	public DWARFMacroOpcode getOpcode() {
		return opcode;
	}

	public String getName() {
		return opcode != null
				? opcode.getDescription()
				: "DW_MACRO_unknown[%x]".formatted(rawOpcode);
	}

	public <T extends DWARFAttributeValue> T getOperand(int index, Class<T> valueClass)
			throws IOException {
		DWARFAttributeValue val = operandValues[index];
		if (valueClass.isInstance(val)) {
			return valueClass.cast(val);
		}
		throw new IOException("Incompatible operand type %s for %s"
				.formatted(valueClass.getSimpleName(), toString()));
	}

	protected DWARFAttributeDef<DWARFMacroOpcode> operandDef(int operandIndex) {
		// TODO: we are re-using the opcode's enum as the identity of each operand value, which
		// isn't technically correct.
		return new DWARFMacroOpcode.Def(opcode, rawOpcode, opcode.getOperandForms()[operandIndex]);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getName());
		if (operandValues.length > 0) {
			sb.append(": ");
			for (int i = 0; i < operandValues.length; i++) {
				if (i != 0) {
					sb.append(", ");
				}
				sb.append(operandValues[i].getValueString(macroHeader.getCompilationUnit()));
			}
		}

		return sb.toString();
	}

}
