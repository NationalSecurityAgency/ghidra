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
package ghidra.file.formats.android.oat.oatclass;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.dex.format.ClassDataItem;
import ghidra.file.formats.android.oat.oatmethod.OatMethodOffsetsFactory;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/oat_file.h#205">lollipop-release/runtime/oat_file.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-fi-release/runtime/oat_file.h#202">lollipop-mr1-fi-release/runtime/oat_file.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-wear-release/runtime/oat_file.h#211">lollipop-wear-release/runtime/oat_file.h</a>
 */
public class OatClass_Lollipop extends OatClass {

	private int bitmap_size_;
	private byte[] bitmap_ = new byte[0];

	OatClass_Lollipop(BinaryReader reader, ClassDataItem classDataItem, String oatVersion)
			throws IOException {

		super(reader, oatVersion);

		type_ = reader.readNextShort();

		int methodOffsetsCount = 0;

		if (type_ == OatClassType.kOatClassSomeCompiled.ordinal()) {
			bitmap_size_ = reader.readNextInt();
			bitmap_ = reader.readNextByteArray(bitmap_size_);

			//For every set bit, there will be a corresponding entry in method_offsets.;
			for (int i = 0; i < bitmap_size_; ++i) {
				methodOffsetsCount += Integer.bitCount(Byte.toUnsignedInt(bitmap_[i]));
			}
		}
		else if (type_ == OatClassType.kOatClassAllCompiled.ordinal()) {
			methodOffsetsCount =
				classDataItem.getDirectMethodsSize() + classDataItem.getVirtualMethodsSize();
		}

		for (int i = 0; i < methodOffsetsCount; ++i) {
			methods_pointer_.add(OatMethodOffsetsFactory.getOatMethodOffsets(reader, oatVersion));
		}
	}

	/**
	 * Size of compiled methods bitmap (present only when type = 1)
	 * @return size of methods bitmap
	 */
	public int getBitmapSize() {
		return bitmap_size_;
	}

	/**
	 * Compiled methods bitmap (present only when type = 1)
	 * @return methods bitmap
	 */
	public byte[] getBitmap() {
		return bitmap_;
	}

	/**
	 * Returns true if this method index is declared native in the bitmap
	 * @param methodIndex the method index
	 * @return true if this method index is declared native in the bitmap
	 */
	public boolean isMethodNative(int methodIndex) {
		int bytePos = methodIndex / 8;
		int bitPos = methodIndex % 8;
		return (((bitmap_[bytePos] >> bitPos) & 0x1) == 0x1);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = OatClass_Lollipop.class.getSimpleName();

		if (bitmap_size_ > 0) {
			className += "_" + bitmap_size_;
		}
		if (methods_pointer_.size() > 0) {
			className += "_" + methods_pointer_.size();
		}

		Structure structure = new StructureDataType(className, 0);

		structure.add(statusEnum.toDataType(), "status_", null);
		structure.add(WORD, "type_", null);

		if (type_ == OatClassType.kOatClassSomeCompiled.ordinal()) {
			structure.add(DWORD, "bitmap_size_", null);
			if (bitmap_size_ > 0) {
				DataType bitmapDataType = new ArrayDataType(BYTE, bitmap_size_, BYTE.getLength());
				structure.add(bitmapDataType, "bitmap_", null);
			}
		}

		for (int i = 0; i < methods_pointer_.size(); ++i) {
			structure.add(methods_pointer_.get(i).toDataType(), "methods_pointer_" + i, null);
		}

		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
