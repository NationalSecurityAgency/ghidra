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
package ghidra.file.formats.android.cdex;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.dex.format.CodeItem;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/libdexfile/dex/compact_dex_file.h
 * <br>
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/compact_dex_file.h
 */
public class CDexCodeItem extends CodeItem {

	public final static short kRegistersSizeShift = 12;
	public final static short kInsSizeShift = 8;
	public final static short kOutsSizeShift = 4;
	public final static short kTriesSizeSizeShift = 0;
	public final static short kInsnsSizeShift = 5;

	public final static short kBitPreHeaderRegisterSize = 0;
	public final static short kBitPreHeaderInsSize = 1;
	public final static short kBitPreHeaderOutsSize = 2;
	public final static short kBitPreHeaderTriesSize = 3;
	public final static short kBitPreHeaderInsnsSize = 4;
	public final static short kFlagPreHeaderRegisterSize = 0x1 << kBitPreHeaderRegisterSize;
	public final static short kFlagPreHeaderInsSize = 0x1 << kBitPreHeaderInsSize;
	public final static short kFlagPreHeaderOutsSize = 0x1 << kBitPreHeaderOutsSize;
	public final static short kFlagPreHeaderTriesSize = 0x1 << kBitPreHeaderTriesSize;
	public final static short kFlagPreHeaderInsnsSize = 0x1 << kBitPreHeaderInsnsSize;

	public final static short kFlagPreHeaderCombined =
		kFlagPreHeaderRegisterSize | kFlagPreHeaderInsSize | kFlagPreHeaderOutsSize |
			kFlagPreHeaderTriesSize | kFlagPreHeaderInsnsSize;

	private short fields_;
	private short insns_count_and_flags_;

	public CDexCodeItem(BinaryReader reader) throws IOException {
		super();

		long startIndex = reader.getPointerIndex();//used for reading preheaders...

		/*
		 * Packed code item data,
		 * 4 bits each: [registers_size, ins_size, outs_size, tries_size]
		 */
		fields_ = reader.readNextShort();

		registersSize = (short) ((fields_ >> kRegistersSizeShift) & 0xf);
		incomingSize = (short) ((fields_ >> kInsSizeShift) & 0xf);
		outgoingSize = (short) ((fields_ >> kOutsSizeShift) & 0xf);
		triesSize = (short) ((fields_ >> kOutsSizeShift) & 0xf);

		/*
		 * 5 bits, if either of the fields required preheader extension, 
		 * 11 bits for the number of instruction code units.
		 */
		insns_count_and_flags_ = reader.readNextShort();

		instructionSize = (Short.toUnsignedInt(insns_count_and_flags_) >> kInsnsSizeShift);

		if (hasPreHeader()) {
			if (hasPreHeader(kFlagPreHeaderInsnsSize)) {
				startIndex -= 2;
				instructionSize += reader.readShort(startIndex);
				startIndex -= 2;
				instructionSize += (reader.readShort(startIndex) << 16);
			}
			if (hasPreHeader(kFlagPreHeaderRegisterSize)) {
				startIndex -= 2;
				registersSize += reader.readShort(startIndex);
			}
			if (hasPreHeader(kFlagPreHeaderInsSize)) {
				startIndex -= 2;
				incomingSize += reader.readShort(startIndex);
			}
			if (hasPreHeader(kFlagPreHeaderOutsSize)) {
				startIndex -= 2;
				outgoingSize += reader.readShort(startIndex);
			}
			if (hasPreHeader(kFlagPreHeaderTriesSize)) {
				startIndex -= 2;
				triesSize += reader.readShort(startIndex);
			}
		}

		if (getInstructionSize() == 0) {
			instructionBytes = new byte[0];
			instructions = new short[0];
		}
		else {
			instructionBytes = reader.readNextByteArray(getInstructionSize() * 2);
			instructions = reader.readNextShortArray(getInstructionSize());
		}

	}

	public boolean hasPreHeader() {
		return (insns_count_and_flags_ & kFlagPreHeaderCombined) != 0;
	}

	public boolean hasPreHeader(short flag) {
		return (insns_count_and_flags_ & flag) != 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "cdex_code_item" + "_" + (getInstructionSize() * 2);
		Structure structure = new StructureDataType(name, 0);
		structure.add(WORD, "fields_", null);
		structure.add(WORD, "insns_count_and_flags_", null);
		if (getInstructionSize() > 0) {
			structure.add(new ArrayDataType(WORD, getInstructionSize(), WORD.getLength()), "insns_",
				null);
		}
		structure.setCategoryPath(new CategoryPath("/dex/cdex_code_item"));
		return structure;
	}
}
