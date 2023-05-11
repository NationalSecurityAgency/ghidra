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
package ghidra.app.util.bin.format.dwarf4.attribs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf4.DWARFUtil;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFForm;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.app.util.bin.format.dwarf4.next.StringTable;
import ghidra.program.model.data.LEB128;

/**
 * A factory for deserializing {@link DWARFAttributeValue dwarf attribute} from
 * a stream.
 */
public class DWARFAttributeFactory {

	/**
	 * Max number of bytes that dw_form_block4 is allowed to specify, 1Mb.
	 */
	public static final int MAX_BLOCK4_SIZE = 1024 * 1024;

	private DWARFProgram prog;

	public DWARFAttributeFactory(DWARFProgram prog) {
		this.prog = prog;
	}

	/**
	 * Read from the given BinaryReader based on the type of DWARFForm that is given.
	 * @param reader BinaryReader pointing to the value to read
	 * @param unit the current compilation unit
	 * @param form DWARFForm type defining the type of value to read
	 * @return Object representing the value that was read
	 * @throws IOException if an I/O error occurs
	 */
	public DWARFAttributeValue read(BinaryReader reader, DWARFCompilationUnit unit, DWARFForm form)
			throws IOException {
		StringTable debugStrings = prog.getDebugStrings();
		switch (form) {
			case DW_FORM_addr:
				return new DWARFNumericAttribute(
					reader.readNextUnsignedValue(unit.getPointerSize()));
			case DW_FORM_ref1: {
				long uoffset = reader.readNextUnsignedValue(1);
				return new DWARFNumericAttribute(uoffset + unit.getStartOffset());
			}
			case DW_FORM_ref2: {
				long uoffset = reader.readNextUnsignedValue(2);
				return new DWARFNumericAttribute(uoffset + unit.getStartOffset());
			}
			case DW_FORM_ref4: {
				long uoffset = reader.readNextUnsignedValue(4);
				return new DWARFNumericAttribute(uoffset + unit.getStartOffset());
			}
			case DW_FORM_ref8: {
				long uoffset = reader.readNextUnsignedValue(8);
				return new DWARFNumericAttribute(uoffset + unit.getStartOffset());
			}
			case DW_FORM_ref_udata: {
				long uoffset = reader.readNext(LEB128::unsigned);
				return new DWARFNumericAttribute(uoffset + unit.getStartOffset());
			}

				// DW_FORM_ref_addr and DW_FORM_sec_offset have identical raw forms,
				// but point to different items (ref_addr points to elements in .debug_info,
				// sec_offset points to elements in other sections) 
			case DW_FORM_ref_addr:
				return new DWARFNumericAttribute(
					DWARFUtil.readOffsetByDWARFformat(reader, unit.getFormat()));
			case DW_FORM_sec_offset:
				return new DWARFNumericAttribute(
					DWARFUtil.readOffsetByDWARFformat(reader, unit.getFormat()));

			case DW_FORM_block1: {
				int length = DWARFUtil.readVarSizedUInt(reader, 1);
				return new DWARFBlobAttribute(reader.readNextByteArray(length));
			}
			case DW_FORM_block2: {
				int length = DWARFUtil.readVarSizedUInt(reader, 2);
				return new DWARFBlobAttribute(reader.readNextByteArray(length));
			}
			case DW_FORM_block4: {
				int length = DWARFUtil.readVarSizedUInt(reader, 4);
				if (length < 0 || length > MAX_BLOCK4_SIZE) {
					throw new IOException("Invalid/bad dw_form_block4 size: " + length);
				}
				return new DWARFBlobAttribute(reader.readNextByteArray(length));
			}
			case DW_FORM_block: {
				int length = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
				if (length < 0 || length > MAX_BLOCK4_SIZE) {
					throw new IOException("Invalid/bad dw_form_block size: " + length);
				}
				return new DWARFBlobAttribute(reader.readNextByteArray(length));
			}
			case DW_FORM_data1:
				return new DWARFNumericAttribute(8, reader.readNextByte(), true, true);
			case DW_FORM_data2:
				return new DWARFNumericAttribute(16, reader.readNextShort(), true, true);
			case DW_FORM_data4:
				return new DWARFNumericAttribute(32, reader.readNextInt(), true, true);
			case DW_FORM_data8:
				return new DWARFNumericAttribute(64, reader.readNextLong(), true, true);
			case DW_FORM_sdata:
				return new DWARFNumericAttribute(64, reader.readNext(LEB128::signed), true);
			case DW_FORM_udata:
				return new DWARFNumericAttribute(64, reader.readNext(LEB128::unsigned), false);

			case DW_FORM_exprloc: {
				int length = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
				if (length < 0 || length > MAX_BLOCK4_SIZE) {
					throw new IOException("Invalid/bad dw_form_exprloc size: " + length);
				}
				return new DWARFBlobAttribute(reader.readNextByteArray(length));
			}

			case DW_FORM_flag:
				return DWARFBooleanAttribute.get(reader.readNextByte() != 0);
			case DW_FORM_flag_present:
				return DWARFBooleanAttribute.TRUE;

			case DW_FORM_string:
				return new DWARFStringAttribute(reader.readNextUtf8String());
			case DW_FORM_strp:
				// Note: we can either read the string from the string section (via. the 
				// string table) here and put it in a DWARFStringAttribute and hope
				// it is used and not wasted memory, or use a DWARFDeferredStringAttribute 
				// to hold the offset until the string is actually requested in DIEAggregate.getString()
				long stringOffset = DWARFUtil.readOffsetByDWARFformat(reader, unit.getFormat());
				if (!debugStrings.isValid(stringOffset))
					throw new IOException("Bad string offset " + Long.toHexString(stringOffset));
				return new DWARFDeferredStringAttribute(stringOffset);
			//return new DWARFStringAttribute(debugStrings.getStringAtOffset(stringOffset));

			case DW_FORM_ref_sig8:
				throw new UnsupportedOperationException(
					"DW_FORM_ref_sig8 is currently not implemented");

			// Indirect Form
			case DW_FORM_indirect:
				DWARFForm formValue =
					DWARFForm.find(reader.readNextUnsignedVarIntExact(LEB128::unsigned));
				DWARFAttributeValue value = read(reader, unit, formValue);

				return new DWARFIndirectAttribute(value, formValue);
			default:
		}
		throw new IllegalArgumentException("Unknown DWARF Form: " + form.toString());
	}

}
