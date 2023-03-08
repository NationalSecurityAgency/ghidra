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
package ghidra.file.formats.android.dex.format;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.file.formats.android.cdex.CDexCodeItem;
import ghidra.file.formats.android.cdex.CDexHeader;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * 
 * https://source.android.com/devices/tech/dalvik/dex-format#encoded-method
 */
public class EncodedMethod implements StructConverter {

	private long _fileOffset;
	private int _methodIndex;

	private int methodIndexDifference;
	private int accessFlags;
	private int codeOffset;

	private int methodIndexDifferenceLength;// in bytes
	private int accessFlagsLength;// in bytes
	private int codeOffsetLength;// in bytes

	private CodeItem codeItem;

	public EncodedMethod(BinaryReader reader, DexHeader dexHeader) throws IOException {

		LEB128Info leb128 = reader.readNext(LEB128Info::unsigned);
		_fileOffset = leb128.getOffset();
		methodIndexDifference = leb128.asUInt32();
		methodIndexDifferenceLength = leb128.getLength();

		leb128 = reader.readNext(LEB128Info::unsigned);
		accessFlags = leb128.asUInt32();
		accessFlagsLength = leb128.getLength();

		leb128 = reader.readNext(LEB128Info::unsigned);
		codeOffset = leb128.asUInt32();
		codeOffsetLength = leb128.getLength();

		if (codeOffset > 0) {
			long oldIndex = reader.getPointerIndex();
			try {
				reader.setPointerIndex(DexUtil.adjustOffset(codeOffset, dexHeader));
				if (dexHeader instanceof CDexHeader) {
					codeItem = new CDexCodeItem(reader);
				}
				else { //must be actual DexHeader base class
					codeItem = new CodeItem(reader);
				}
			}
			finally {
				reader.setPointerIndex(oldIndex);
			}
		}
	}

	public long getFileOffset() {
		return _fileOffset;
	}

	void setMethodIndex(int methodIndex) {
		_methodIndex = methodIndex;
	}

	public int getMethodIndex() {
		return _methodIndex;
	}

	public int getMethodIndexDifference() {
		return methodIndexDifference;
	}

	public int getAccessFlags() {
		return accessFlags;
	}

	public boolean isStatic() {
		return (accessFlags & AccessFlags.ACC_STATIC) != 0;
	}

	public int getCodeOffset() {
		return codeOffset;
	}

	public CodeItem getCodeItem() {
		return codeItem;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "encoded_method_%d_%d_%d".formatted(methodIndexDifferenceLength,
			accessFlagsLength, codeOffsetLength);
		Structure structure = new StructureDataType(name, 0);
		structure.add(ULEB128, methodIndexDifferenceLength, "method_idx_diff", null);
		structure.add(ULEB128, accessFlagsLength, "access_flags", null);
		structure.add(ULEB128, codeOffsetLength, "code_off", null);
		structure.setCategoryPath(new CategoryPath("/dex/encoded_method"));
		return structure;
	}
}
