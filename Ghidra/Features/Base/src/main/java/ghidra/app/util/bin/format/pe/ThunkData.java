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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the 
 * <b><code>IMAGE_THUNK_DATA32 struct</code></b>
 * as defined in 
 * <b><code>winnt.h</code></b>.
 * 
 * <pre>
 * typedef struct _IMAGE_THUNK_DATA32 {
 *     union {
 *         DWORD ForwarderString;  // PBYTE
 *         DWORD Function;         // PDWORD
 *         DWORD Ordinal;
 *         DWORD AddressOfData;    // PIMAGE_IMPORT_BY_NAME
 *     } u1;
 * } IMAGE_THUNK_DATA32;
 * typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;
 * </pre>
 * 
 * <pre>
 * typedef struct _IMAGE_THUNK_DATA64 {
 *     union {
 *         PBYTE  ForwarderString;
 *         PDWORD Function;
 *         ULONGLONG Ordinal;
 *         PIMAGE_IMPORT_BY_NAME  AddressOfData;
 *     } u1;
 * } IMAGE_THUNK_DATA64;
 * typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;
 * </pre>
 *
 * 
 */
public class ThunkData implements StructConverter, ByteArrayConverter {
	private boolean is64bit;
	private long value;
	private ImportByName ibn;

	ThunkData(BinaryReader reader, int index, boolean is64bit) throws IOException {
		this.is64bit = is64bit;
		if (is64bit) {
			value = reader.readLong(index);
		}
		else {
			value = reader.readUnsignedInt(index);
		}
	}

	/**
	 * Constructs a new thunk data with the specified value
	 * @param value the new thunk value
	 */
	public ThunkData(int value) {
		setValue(value);
	}

	/**
	 * Returns the size of the thunk (in bytes) based on the size of the
	 * executable (32 vs 64 bit).
	 * @return the size of the thunk (in bytes)
	 */
	public int getStructSize() {
		return is64bit ? 8 : 4;
	}

	/**
	 * Returns the struct name.
	 * @return the struct name
	 */
	public String getStructName() {
		return "IMAGE_THUNK_DATA" + (is64bit ? "64" : "32");
	}

	/**
	 * Sets the value of the thunk.
	 * @param value the new thunk value
	 */
	public void setValue(int value) {
		this.value = Integer.toUnsignedLong(value);
	}

	/**
	 * Returns the forward string pointer.
	 * @return the forward string pointer
	 */
	public long getForwarderString() {
		return value;
	}

	/**
	 * Returns the function pointer.
	 * @return the function pointer
	 */
	public long getFunction() {
		return value;
	}

	/**
	 * Returns the ordinal.
	 * @return the ordinal
	 */
	public long getOrdinal() {
		return value & 0xffff;
	}

	public boolean isOrdinal() {
		if (is64bit) {
			return (value & Constants.IMAGE_ORDINAL_FLAG64) != 0;
		}
		return (value & Constants.IMAGE_ORDINAL_FLAG32) != 0;
	}

	/**
	 * Returns the address of the data.
	 * @return the address of the data
	 */
	public long getAddressOfData() {
		return value;
	}

	void setImportByName(ImportByName ibn) {
		this.ibn = ibn;
	}

	/**
	 * Returns the underlying import by name structure.
	 * @return the underlying import by name structure
	 */
	public ImportByName getImportByName() {
		return ibn;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		UnionDataType union = new UnionDataType("u1");
		union.setCategoryPath(new CategoryPath("/PE"));

		DataType dt = is64bit ? QWORD : DWORD;

		union.add(dt, "ForwarderString", null);
		union.add(dt, "Function", null);
		union.add(dt, "Ordinal", null);
		union.add(dt, "AddressOfData", null);

		StructureDataType struct = new StructureDataType(getStructName(), 0);
		struct.add(union, "u1", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	@Override
	public byte[] toBytes(DataConverter dc) {
		if (is64bit) {
			return dc.getBytes(value);
		}
		int tmp = (int) value;
		return dc.getBytes(tmp);
	}

}
