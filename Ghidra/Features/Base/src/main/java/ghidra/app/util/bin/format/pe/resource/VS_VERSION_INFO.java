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
package ghidra.app.util.bin.format.pe.resource;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.*;

/**
 * A class to represent the VS_VERSION_INFO data structure.
 */
public class VS_VERSION_INFO implements StructConverter {
	public final static String NAME = "VS_VERSION_INFO";
	public final static int SIZEOF = 92;

	private short structLength;
	private short valueLength;
	private short structType;
	private String info;
	private int alignment;
	private int signature;
	private String structVersion;
	private String fileVersion;
	private String productVersion;
	private String fileFlagsMask;
	private int fileFlags;
	private int fileOS;
	private int fileType;
	private int fileSubtype;
	private int fileTimestamp;

	private ArrayList<VS_VERSION_CHILD> children = new ArrayList<VS_VERSION_CHILD>();
	private HashMap<String, String> valueMap = new HashMap<String, String>();

	/**
	 * Constructs a new VS_VERSION_INFO object.
	 * @param reader the binary reader
	 * @param index the index where the VS_VERSION_INFO begins
	 * @throws IOException if an I/O error occurs
	 */
	public VS_VERSION_INFO(FactoryBundledWithBinaryReader reader, int index) throws IOException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);

		structLength = reader.readNextShort();
		valueLength = reader.readNextShort();
		structType = reader.readNextShort();
		info = reader.readNextUnicodeString();

		alignment = reader.align(4);

		// start of VS_FIXEDFILEINFO
		signature = reader.readNextInt();
		structVersion = shortArrayToString(reader, 2);
		fileVersion = shortArrayToString(reader, 4);
		productVersion = shortArrayToString(reader, 4);
		fileFlagsMask = intArrayToString(reader, 2);
		fileFlags = reader.readNextInt();
		fileOS = reader.readNextInt();
		fileType = reader.readNextInt();
		fileSubtype = reader.readNextInt();
		fileTimestamp = reader.readNextInt();

		while (reader.getPointerIndex() < index + structLength) {
			// TODO: is alignment needed?
			children.add(new VS_VERSION_CHILD(reader, reader.getPointerIndex() - index, null,
				valueMap));
		}

		reader.setPointerIndex(oldIndex);
	}

	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "StructLength", null);
		struct.add(WORD, "ValueLength", null);
		struct.add(WORD, "StructType", null);
		struct.add(UTF16, (info.length() + 1) * 2, "Info", null);
		if (alignment > 0) {
			struct.add(new ArrayDataType(BYTE, alignment, BYTE.getLength()), "Padding", null);
		}
		struct.add(DWORD, "Signature", null);
		struct.add(new ArrayDataType(WORD, 2, WORD.getLength()), "StructVersion", null);
		struct.add(new ArrayDataType(WORD, 4, WORD.getLength()), "FileVersion", null);
		struct.add(new ArrayDataType(WORD, 4, WORD.getLength()), "ProductVersion", null);
		struct.add(new ArrayDataType(DWORD, 2, DWORD.getLength()), "FileFlagsMask", null);
		struct.add(DWORD, "FileFlags", null);
		struct.add(DWORD, "FileOS", null);
		struct.add(DWORD, "FileType", null);
		struct.add(DWORD, "FileSubtype", null);
		struct.add(DWORD, "FileTimestamp", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	/**
	 * Returns the array of VS_VERSION_CHILD defined in this VS_VERSION_INFO object.
	 * @return the array of VS_VERSION_CHILD defined in this VS_VERSION_INFO object
	 */
	public VS_VERSION_CHILD[] getChildren() {
		VS_VERSION_CHILD[] arr = new VS_VERSION_CHILD[children.size()];
		children.toArray(arr);
		return arr;
	}

	/**
	 * Returns the file flags.
	 * @return the file flags
	 */
	public int getFileFlags() {
		return fileFlags;
	}

	/**
	 * Returns the file flags mask.
	 * @return the file flags mask
	 */
	public String getFileFlagsMask() {
		return fileFlagsMask;
	}

	/**
	 * Returns the file OS.
	 * @return the file OS
	 */
	public int getFileOS() {
		return fileOS;
	}

	/**
	 * Returns the file sub-type.
	 * @return the file sub-type
	 */
	public int getFileSubtype() {
		return fileSubtype;
	}

	/**
	 * Returns the file timestamp.
	 * @return the file timestamp
	 */
	public int getFileTimestamp() {
		return fileTimestamp;
	}

	/**
	 * Returns the file type.
	 * @return the file type
	 */
	public int getFileType() {
		return fileType;
	}

	/**
	 * Returns the file version.
	 * @return the file version
	 */
	public String getFileVersion() {
		return fileVersion;
	}

	/**
	 * Returns the info.
	 * @return the info
	 */
	public String getInfo() {
		return info;
	}

	/**
	 * Returns the product version.
	 * @return the product version
	 */
	public String getProductVersion() {
		return productVersion;
	}

	/**
	 * Returns the signature.
	 * @return the signature
	 */
	public int getSignature() {
		return signature;
	}

	/**
	 * Returns the structure length.
	 * @return the structure length
	 */
	public short getStructLength() {
		return structLength;
	}

	/**
	 * Returns the structure type.
	 * @return the structure type
	 */
	public short getStructType() {
		return structType;
	}

	/**
	 * Returns the structure version.
	 * @return the structure version
	 */
	public String getStructVersion() {
		return structVersion;
	}

	/**
	 * Returns the value length.
	 * @return the value length
	 */
	public short getValueLength() {
		return valueLength;
	}

	/**
	 * Returns the array of keys in this version child.
	 * @return the array of keys in this version child
	 */
	public String[] getKeys() {
		String[] keys = new String[valueMap.size()];
		Iterator<String> iter = valueMap.keySet().iterator();
		int i = 0;
		while (iter.hasNext()) {
			keys[i++] = iter.next();
		}
		Arrays.sort(keys);
		return keys;
	}

	/**
	 * Returns the value for the specified key.
	 * @param key the key
	 * @return the value for the specified key
	 */
	public String getValue(String key) {
		return valueMap.get(key);
	}

	static String shortArrayToString(FactoryBundledWithBinaryReader reader, int nElements)
			throws IOException {
		if (nElements == 2) {
			short[] arr = reader.readNextShortArray(2);
			return arr[1] + "." + arr[0];
		}
		else if (nElements == 4) {
			short[] arr = reader.readNextShortArray(4);
			return arr[1] + "." + arr[0] + "." + arr[3] + "." + arr[2];
		}
		return null;
	}

	static String intArrayToString(FactoryBundledWithBinaryReader reader, int nElements)
			throws IOException {
		if (nElements == 2) {
			int[] arr = reader.readNextIntArray(2);
			return arr[1] + "." + arr[0];
		}
		else if (nElements == 4) {
			int[] arr = reader.readNextIntArray(4);
			return arr[1] + "." + arr[0] + "." + arr[3] + "." + arr[2];
		}
		return null;
	}
}
