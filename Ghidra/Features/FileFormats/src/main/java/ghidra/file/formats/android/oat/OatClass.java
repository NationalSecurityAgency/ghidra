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
package ghidra.file.formats.android.oat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.file.formats.android.dex.format.ClassDataItem;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * 
 * https://android.googlesource.com/platform/art/+/kitkat-release/runtime/oat_file.h#144
 * 
 * https://android.googlesource.com/platform/art/+/lollipop-release/runtime/oat_file.h#205
 * 
 * https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/oat_file.h#200
 *
 */
public class OatClass implements StructConverter {

	private String oatVersion;

	private short status;
	private short type;
	private int bitmapSize;
	private byte[] bitmap = new byte[0];
	private List<OatMethodOffsets> methodOffsets = new ArrayList<OatMethodOffsets>();

	OatClass(BinaryReader reader, ClassDataItem classDataItem, String oatVersion)
			throws IOException {
		this.oatVersion = oatVersion;

		status = reader.readNextShort();
		type = reader.readNextShort();

		int methodOffsetsCount = 0;

		if (type == OatClassType.kOatClassSomeCompiled.ordinal()) {
			bitmapSize = reader.readNextInt();
			bitmap = reader.readNextByteArray(bitmapSize);

			//For every set bit, there will be a corresponding entry in method_offsets.;
			for (int i = 0; i < bitmapSize; ++i) {
				methodOffsetsCount += Integer.bitCount(Byte.toUnsignedInt(bitmap[i]));
			}
		}
		else if (type == OatClassType.kOatClassAllCompiled.ordinal()) {
			methodOffsetsCount =
				classDataItem.getDirectMethodsSize() + classDataItem.getVirtualMethodsSize();
		}

		for (int i = 0; i < methodOffsetsCount; ++i) {
			methodOffsets.add(OatMethodOffsetsFactory.getOatMethodOffsets(reader, oatVersion));
		}
	}

	/**
	 * State of class during compilation
	 * @return the class status
	 */
	public short getStatus() {
		return status;
	}

	/**
	 * Returns the class type
	 * @return the OAT class type
	 * @see OatClassType
	 */
	public short getType() {
		return type;
	}

	/**
	 * Size of compiled methods bitmap (present only when type = 1)
	 * @return size of methods bitmap
	 */
	public int getBitmapSize() {
		return bitmapSize;
	}

	/**
	 * Compiled methods bitmap (present only when type = 1)
	 * @return methods bitmap
	 */
	public byte[] getBitmap() {
		return bitmap;
	}

	/**
	 * Returns true if this method index is declared native in the bitmap
	 * @param methodIndex the method index
	 * @return true if this method index is declared native in the bitmap
	 */
	public boolean isMethodNative(int methodIndex) {
		int bytePos = methodIndex / 8;
		int bitPos = methodIndex % 8;
		return (((bitmap[bytePos] >> bitPos) & 0x1) == 0x1);
	}

	/**
	 * methodOffsets is a list of offset that points to the generated
	 * native code for each compiled method.    
	 * @return list of method offsets
	 */
	public List<OatMethodOffsets> getMethodOffsets() {
		return methodOffsets;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(OatClass.class);

		if (bitmapSize > 0) {
			className += "_" + bitmapSize;
		}
		if (methodOffsets.size() > 0) {
			className += "_" + methodOffsets.size();
		}

		Structure structure = new StructureDataType(className, 0);

		//structure.add( WORD, "status", null );
		if (oatVersion.equals(OatConstants.VERSION_OREO_M2_RELEASE)) {
			structure.add(OatClassStatus_OreoM2.toDataType(), "status", null);
		}
		else {
			structure.add(OatClassStatus.toDataType(), "status", null);
		}

		structure.add(WORD, "type", null);

		if (type == OatClassType.kOatClassSomeCompiled.ordinal()) {
			structure.add(DWORD, "bitmapSize", null);
			if (bitmapSize > 0) {
				DataType bitmapDataType = new ArrayDataType(BYTE, bitmapSize, BYTE.getLength());
				structure.add(bitmapDataType, "bitmap", null);
			}
		}

		for (int i = 0; i < methodOffsets.size(); ++i) {
			structure.add(methodOffsets.get(i).toDataType(), "methodOffsets_" + i, null);
		}

		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
