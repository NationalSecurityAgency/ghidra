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
package ghidra.app.util.bin.format.pe.debug;

import java.io.IOException;
import java.io.RandomAccessFile;

import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.OffsetValidator;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the Debug Directory data structure.
 * <br>
 * <pre>
 * typedef struct _IMAGE_DEBUG_DIRECTORY {
 *     DWORD   Characteristics;
 *     DWORD   TimeDateStamp;
 *     WORD    MajorVersion;
 *     WORD    MinorVersion;
 *     DWORD   Type;
 *     DWORD   SizeOfData;
 *     DWORD   AddressOfRawData;
 *     DWORD   PointerToRawData;
 * } IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
 * </pre>
 * <br>
 */
public class DebugDirectory implements StructConverter, ByteArrayConverter {
	/**
	 * The name to use when converting into a structure data type.
	 */
	public final static String NAME = "IMAGE_DEBUG_DIRECTORY";
	/**
	 * The size of the <code>IMAGE_DEBUG_DIRECTORY</code>, in bytes.
	 */
	public final static int IMAGE_SIZEOF_DEBUG_DIRECTORY = 28;

	private int characteristics;
	private int timeDateStamp;
	private short majorVersion;
	private short minorVersion;
	private int type;
	private int sizeOfData;
	private int addressOfRawData;
	private int pointerToRawData;

	private String description;

	private byte[] blobBytes;
	private long index = 0;

	/**
	 * Constuctor.
	 * @param reader the binary reader
	 * @param index the index where this debug directory begins
	 * @param ntHeader 
	 */
	static DebugDirectory createDebugDirectory(FactoryBundledWithBinaryReader reader, long index,
			OffsetValidator validator) throws IOException {
		DebugDirectory debugDirectory =
			(DebugDirectory) reader.getFactory().create(DebugDirectory.class);
		debugDirectory.initDebugDirectory(reader, index, validator);
		return debugDirectory;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DebugDirectory() {
	}

	private void initDebugDirectory(FactoryBundledWithBinaryReader reader, long index,
			OffsetValidator validator) throws IOException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);

		characteristics = reader.readNextInt();
		timeDateStamp = reader.readNextInt();
		majorVersion = reader.readNextShort();
		minorVersion = reader.readNextShort();
		type = reader.readNextInt();
		sizeOfData = reader.readNextInt();
		addressOfRawData = reader.readNextInt();
		pointerToRawData = reader.readNextInt();

		if (type < 0 || type > 16 || sizeOfData < 0) {
			Msg.error(this, "Invalid DebugDirectory");
			sizeOfData = 0;
			reader.setPointerIndex(oldIndex);
			return;
		}
		if (sizeOfData > 0) {
			if (!validator.checkPointer(pointerToRawData)) {
				Msg.error(this, "Invalid pointerToRawData " + pointerToRawData);
				sizeOfData = 0;
				reader.setPointerIndex(oldIndex);
				return;
			}
			blobBytes = reader.readByteArray(pointerToRawData, sizeOfData);
		}

		this.index = index;
		reader.setPointerIndex(oldIndex);
	}

	/**
	 * Reserved.
	 * @return reserved value
	 */
	public int getCharacteristics() {
		return characteristics;
	}

	/**
	 * Returns the time and date the debugging information was created. 
	 * @return the time and date the debugging information was created
	 */
	public int getTimeDateStamp() {
		return timeDateStamp;
	}

	/**
	 * Returns the major version number of the debugging information format.
	 * @return the major version number of the debugging information format
	 */
	public int getMajorVersion() {
		return majorVersion;
	}

	/**
	 * Returns the minor version number of the debugging information format.
	 * @return the minor version number of the debugging information format
	 */
	public int getMinorVersion() {
		return minorVersion;
	}

	/**
	 * Returns the format of the debugging information.
	 * @return the format of the debugging information
	 */
	public int getType() {
		return type;
	}

	/**
	 * Returns the size of the debugging information, in bytes. 
	 * This value does not include the debug directory itself.
	 * @return the size of the debugging information, in bytes
	 */
	public int getSizeOfData() {
		return sizeOfData;
	}

	/**
	 * Returns the address of the debugging information when the image is loaded, relative to the image base.
	 * @return the address of the debugging information when the image is loaded, relative to the image base
	 */
	public int getAddressOfRawData() {
		return addressOfRawData;
	}

	/**
	 * Returns the file pointer to the debugging information.
	 * @return the file pointer to the debugging information
	 */
	public int getPointerToRawData() {
		return pointerToRawData;
	}

	/**
	 * Returns a description of this debug directory.
	 * @return a description of this debug directory
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Sets the description of this debug directory.
	 * @param desc the description of this debug directory
	 */
	public void setDescription(String desc) {
		this.description = desc;
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(DWORD, "Characteristics", null);
		struct.add(DWORD, "TimeDateStamp", null);
		struct.add(WORD, "MajorVersion", null);
		struct.add(WORD, "MinorVersion", null);
		struct.add(DWORD, "Type", null);
		struct.add(DWORD, "SizeOfData", null);
		struct.add(DWORD, "AddressOfRawData", null);
		struct.add(DWORD, "PointerToRawData", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	public void writeHeader(RandomAccessFile raf, DataConverter dc) throws IOException {
		//TODO: This is no longer correct
		raf.seek(index);
		raf.write(dc.getBytes(characteristics));
		raf.write(dc.getBytes(timeDateStamp));
		raf.write(dc.getBytes(majorVersion));
		raf.write(dc.getBytes(minorVersion));
		raf.write(dc.getBytes(type));
		raf.write(dc.getBytes(sizeOfData));
		raf.write(dc.getBytes(addressOfRawData));
		raf.write(dc.getBytes(pointerToRawData));
	}

	@Override
	public byte[] toBytes(DataConverter dc) {
		if (blobBytes == null) {
			return new byte[0];
		}
		return blobBytes;
	}

	public void updatePointers(int offset, int postOffset) {
		Msg.debug(this, index + "+" + offset + " " + pointerToRawData + "+" + postOffset);
		index += offset;
		pointerToRawData += postOffset;
	}
}
