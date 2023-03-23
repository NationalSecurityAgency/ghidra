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
import ghidra.util.NumericUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/oat_file.h#283">android12-release/runtime/oat_file.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android13-release/runtime/oat_file.h#279">android13-release/runtime/oat_file.h</a>
 */
public class OatClass_S_T extends OatClass {

	//https://android.googlesource.com/platform/art/+/master/libartbase/base/bit_vector.h#38
	public static final int kWordBytes = 4;

	private int num_methods_;

	private byte[] bitmap_ = new byte[0];

	OatClass_S_T(BinaryReader reader, ClassDataItem classDataItem, String oatVersion)
			throws IOException {

		super(reader, oatVersion);

		type_ = reader.readNextShort();

		if (type_ == OatClassType.kOatClassNoneCompiled.ordinal()) {
			return;
		}

		num_methods_ = reader.readNextInt();

		int methodOffsetsCount = 0;

		if (type_ == OatClassType.kOatClassSomeCompiled.ordinal()) {
			bitmap_ = reader.readNextByteArray(getBitmapSize());

			//For every set bit, there will be a corresponding entry in method_offsets.;
			for (int i = 0; i < bitmap_.length; ++i) {
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

	public int getNumMethods() {
		return num_methods_;
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
		int bytePos = (methodIndex / 8);
		int bitPos = methodIndex % 8;
		return (((bitmap_[bytePos] >> bitPos) & 0x1) == 0x1);
	}

	/**
	 * Computes the number of bytes required to store the bitmap.
	 * @return the number of bytes required to store the bitmap
	 */
	private int getBitmapSize() {
		if (num_methods_ == 0) {
			return 0;
		}
		int size = (int)NumericUtilities.getUnsignedAlignedValue(num_methods_, 32);
		return size / 8;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = OatClass_S_T.class.getSimpleName();

		if (methods_pointer_.size() > 0) {
			className += "_" + methods_pointer_.size();
		}
		if (bitmap_.length > 0) {
			className += "_" + bitmap_.length;
		}

		Structure structure = new StructureDataType(className, 0);
		structure.add(statusEnum.toDataType(), "status_", null);
		structure.add(OatClassType.toData(), "type", null);

		if (type_ != OatClassType.kOatClassNoneCompiled.ordinal()) {
			structure.add(DWORD, "num_methods_", null);

			if (type_ == OatClassType.kOatClassSomeCompiled.ordinal()) {
				if (bitmap_.length > 0) {
					DataType bitmapDataType =
						new ArrayDataType(BYTE, bitmap_.length, BYTE.getLength());
					structure.add(bitmapDataType, "bitmap", null);
				}
			}

			for (int i = 0; i < methods_pointer_.size(); ++i) {
				structure.add(methods_pointer_.get(i).toDataType(), "methods_pointer_" + i, null);
			}
		}

		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
