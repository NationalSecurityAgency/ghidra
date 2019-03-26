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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.Conv;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the IMAGE_TLS_DIRECTORY32 and
 * IMAGE_TLS_DIRECTORY64 data structures.
 * <br>
 * <pre>
 * typedef struct _IMAGE_TLS_DIRECTORY32 {
 *     DWORD   StartAddressOfRawData;
 *     DWORD   EndAddressOfRawData;
 *     DWORD   AddressOfIndex;             // PDWORD
 *     DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
 *     DWORD   SizeOfZeroFill;
 *     DWORD   Characteristics;
 * } IMAGE_TLS_DIRECTORY32;
 * typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;
 * </pre>
 * <br>
 * <pre>
 * typedef struct _IMAGE_TLS_DIRECTORY64 {
 *     ULONGLONG   StartAddressOfRawData;
 *     ULONGLONG   EndAddressOfRawData;
 *     PDWORD      AddressOfIndex;
 *     PIMAGE_TLS_CALLBACK * AddressOfCallBacks;
 *     DWORD       SizeOfZeroFill;
 *     DWORD       Characteristics;
 * } IMAGE_TLS_DIRECTORY64;
 * typedef IMAGE_TLS_DIRECTORY64 * PIMAGE_TLS_DIRECTORY64;
 * </pre>
 * <br>
 * 
 */
public class TLSDirectory implements StructConverter {
    private boolean is64bit;
    private long  startAddressOfRawData;
    private long  endAddressOfRawData;
    private long  addressOfIndex;
    private long  addressOfCallBacks;
    private int   sizeOfZeroFill;
    private int   characteristics;

    static TLSDirectory createTLSDirectory(
            FactoryBundledWithBinaryReader reader, int index, boolean is64bit)
            throws IOException {
        TLSDirectory tlsDirectory = (TLSDirectory) reader.getFactory().create(TLSDirectory.class);
        tlsDirectory.initTLSDirectory(reader, index, is64bit);
        return tlsDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public TLSDirectory() {}

    private void initTLSDirectory(FactoryBundledWithBinaryReader reader, int index, boolean is64bit) throws IOException {
        this.is64bit = is64bit;
        if (is64bit) {
	        startAddressOfRawData = reader.readLong(index); index += BinaryReader.SIZEOF_LONG;
	        endAddressOfRawData   = reader.readLong(index); index += BinaryReader.SIZEOF_LONG;
	        addressOfIndex        = reader.readLong(index); index += BinaryReader.SIZEOF_LONG;
	        addressOfCallBacks    = reader.readLong(index); index += BinaryReader.SIZEOF_LONG;
        }
        else {
	        startAddressOfRawData = reader.readInt(index) & Conv.INT_MASK; index += BinaryReader.SIZEOF_INT;
	        endAddressOfRawData   = reader.readInt(index) & Conv.INT_MASK; index += BinaryReader.SIZEOF_INT;
	        addressOfIndex        = reader.readInt(index) & Conv.INT_MASK; index += BinaryReader.SIZEOF_INT;
	        addressOfCallBacks    = reader.readInt(index) & Conv.INT_MASK; index += BinaryReader.SIZEOF_INT;
        }
        Msg.info(this, "TLS callbacks at "+Long.toHexString(addressOfCallBacks));
        sizeOfZeroFill        = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        characteristics       = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
    }

	/**
	 * Returns the beginning address of a range of memory used to initialize a new thread's TLS data in memory.
	 * @return the beginning address of a range of memory used to initialize a new thread's TLS data in memory.
	 */
    public long getStartAddressOfRawData() {
        return startAddressOfRawData;
    }

	/**
	 * Returns the ending address of the range of memory used to initialize a new thread's TLS data in memory.
	 * @return the ending address of the range of memory used to initialize a new thread's TLS data in memory.
	 */
    public long getEndAddressOfRawData() {
        return endAddressOfRawData;
    }

	/**
	 * @return the index to locate the thread local data.
	 */
    public long getAddressOfIndex() {
        return addressOfIndex;
    }

	/**
	 * @return the address of an array of <code>PIMAGE_TLS_CALLBACK</code> function pointers
	 */
    public long getAddressOfCallBacks() {
        return addressOfCallBacks;
    }

	/**
	 * @return the size in bytes of the initialization data
	 */
    public int getSizeOfZeroFill() {
        return sizeOfZeroFill;
    }

	/**
	 * Reserved, currently set to 0.
	 * @return reserved, currently set to 0
	 */
    public int getCharacteristics() {
        return characteristics;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(getName(), 0);

        DataType dt = is64bit ? QWORD : DWORD;

        struct.add(dt, "StartAddressOfRawData", null);
        struct.add(dt, "EndAddressOfRawData", null);
        struct.add(dt, "AddressOfIndex", null);
        struct.add(dt, "AddressOfCallBacks", null);

        struct.add(DWORD, "SizeOfZeroFill", null);
        struct.add(DWORD, "Characteristics", null);

        struct.setCategoryPath(new CategoryPath("/PE"));

        return struct;
    }

	/**
	 * Returns the name of the structure.
	 * @return the name of the structure
	 */
	public String getName() {
	    return "IMAGE_THUNK_DATA"+(is64bit ? "64" : "32");
	}
}
