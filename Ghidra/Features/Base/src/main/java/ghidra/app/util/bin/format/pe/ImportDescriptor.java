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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

/**
 * <pre>
 * typedef struct _IMAGE_IMPORT_DESCRIPTOR {
 *     union {
 *         DWORD   Characteristics;            // 0 for terminating null import descriptor
 *         DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
 *     };
 *     DWORD   TimeDateStamp;
 *     DWORD   ForwarderChain;                 // -1 if no forwarders
 *     DWORD   Name;
 *     DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
 * }
 * </pre>
 * 
 * 
 */
public class ImportDescriptor implements StructConverter, ByteArrayConverter {
    public final static String NAME = "IMAGE_IMPORT_DESCRIPTOR";
    public final static int SIZEOF = 20; //bytes
	public final static int NOT_BOUND = 0;

    private int characteristics;
    private int originalFirstThunk;
    private int timeDateStamp;
    private int forwarderChain;
    private int name;
    private int firstThunk;

	private String dll;

	private List<ThunkData> intList = new ArrayList<ThunkData>();
	private List<ThunkData> iatList = new ArrayList<ThunkData>();

    static ImportDescriptor createImportDescriptor(
            FactoryBundledWithBinaryReader reader, int index)
            throws IOException {
        ImportDescriptor importDescriptor = (ImportDescriptor) reader.getFactory().create(ImportDescriptor.class);
        importDescriptor.initImportDescriptor(reader, index);
        return importDescriptor;
    }

    private void initImportDescriptor(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        characteristics    = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        originalFirstThunk = characteristics;
        timeDateStamp      = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        forwarderChain     = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        name               = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        firstThunk         = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
    }

    /**
     * Constructs a new import descriptor initialized to zero.
     */
	public ImportDescriptor() {
		this.characteristics    = 0;
		this.originalFirstThunk = 0;
		this.timeDateStamp      = 0;
		this.forwarderChain     = 0;
		this.name               = 0;
		this.firstThunk         = 0;
	}

	void setDLL(String dll) {
		this.dll = dll;
	}

	public String getDLL() {
		return dll;
	}

	void addImportNameTableThunkData(ThunkData thunk) {
		intList.add(thunk);
	}

	void addImportAddressTableThunkData(ThunkData thunk) {
		iatList.add(thunk);
	}

	/**
	 * Returns the array of thunks from the import name table.
	 * @return the array of thunks from the import name table
	 */
	public ThunkData [] getImportNameTableThunkData() {
		ThunkData [] data = new ThunkData[intList.size()];
		intList.toArray(data);
		return data;
	}

	/**
	 * Returns the array of thunks from the import address table.
	 * @return the array of thunks from the import address table
	 */
	public ThunkData [] getImportAddressTableThunkData() {
		ThunkData [] data = new ThunkData[iatList.size()];
		iatList.toArray(data);
		return data;
	}

    /**
     * At one time, this may have been a set of flags. 
     * However, Microsoft changed its meaning and 
     * never bothered to update WINNT.H. 
     * This field is really an offset (an RVA) to an 
     * array of pointers. Each of these pointers points 
     * to an IMAGE_IMPORT_BY_NAME structure. 
     * @return an offset (an RVA) to an array of pointers
     */
    public int getCharacteristics() {
        return characteristics;
    }

	/**
	 * At one time, this may have been a set of flags. 
	 * However, Microsoft changed its meaning and 
	 * never bothered to update WINNT.H. 
	 * This field is really an offset (an RVA) to an 
	 * array of pointers. Each of these pointers points 
	 * to an IMAGE_IMPORT_BY_NAME structure. 
	 * @return an offset (an RVA) to an array of pointers
	 */
	public int getOriginalFirstThunk() {
		return originalFirstThunk;
	}

    /**
     * This field is an offset (an RVA) to an 
     * IMAGE_THUNK_DATA union. In almost every case, 
     * the union is interpreted as a pointer to an 
     * IMAGE_IMPORT_BY_NAME structure. If the field 
     * isn't one of these pointers, then it's supposedly 
     * treated as an export ordinal value for the DLL 
     * that's being imported. It's not clear from the 
     * documentation if you really can import a function 
     * by ordinal rather than by name. 
     * @return an offset (an RVA) to an IMAGE_THUNK_DATA union
     */
    public int getFirstThunk() {
        return firstThunk;
    }

    /**
     * This field relates to forwarding. 
     * Forwarding involves one DLL sending on 
     * references to one of its functions to 
     * another DLL. For example, in Windows NT, 
     * NTDLL.DLL appears to forward some of its 
     * exported functions to KERNEL32.DLL. An 
     * application may think it's calling a function 
     * in NTDLL.DLL, but it actually ends up calling 
     * into KERNEL32.DLL. This field contains an index 
     * into FirstThunk array (described momentarily). 
     * The function indexed by this field will be 
     * forwarded to another DLL. Unfortunately, the 
     * format of how a function is forwarded isn't 
     * documented, and examples of forwarded functions 
     * are hard to find. 
     * @return the forwarder chain
     */
    public int getForwarderChain() {
        return forwarderChain;
    }

    /**
     * Returns an RVA to a NULL-terminated 
     * ASCII string containing the imported 
     * DLL's name. Common examples are 
     * "KERNEL32.DLL" and "USER32.DLL".
     * @return an RVA to a NULL-terminated ASCII string
     */
    public int getName() {
        return name;
    }

    /**
     * Returns the time/date stamp indicating when the file was built. 
     * @return the time/date stamp indicating when the file was built 
     */
    public int getTimeDateStamp() {
        return timeDateStamp;
    }

    /**
     * Returns true if the import descriptor is bound to an imported library.
     * Being bound implies that the import has the function's preferred address
     * @return true if the import descriptor is bound
     */
	public boolean isBound() {
		return timeDateStamp != NOT_BOUND;
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException {
        UnionDataType union = new UnionDataType("union");
        union.add(DWORD, "Characteristics",    null);
        union.add(DWORD, "OriginalFirstThunk", null);
        union.setCategoryPath(new CategoryPath("/PE"));

        StructureDataType struct = new StructureDataType(NAME, 0);
        struct.add(union, "union",          null);
        struct.add(DWORD, "TimeDateStamp",  null);
        struct.add(DWORD, "ForwarderChain", null);
        struct.add(DWORD, "Name",           null);
        struct.add(DWORD, "FirstThunk",     null);
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }

    /**
     * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
     */
	public byte [] toBytes(DataConverter dc) {
		byte [] bytes = new byte[SIZEOF];

		int pos = 0;

		dc.getBytes(originalFirstThunk, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;

		dc.getBytes(timeDateStamp, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;

		dc.getBytes(forwarderChain, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;

		dc.getBytes(name, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;

		dc.getBytes(firstThunk, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;

		return bytes;
	}

	/**
	 * Sets the original first thunk to the specifed value. 
	 * @param i the new original first thunk value.
	 * @see #getOriginalFirstThunk()
	 */
	public void setOriginalFirstThunk(int i) {
		originalFirstThunk = i;
	}

	/**
	 * Sets the time/date stamp to the specifed value. 
	 * @param i the new time/date stamp value.
	 * @see #getTimeDateStamp()
	 */
	public void setTimeDateStamp(int i) {
		timeDateStamp = i;
	}

	/**
	 * Sets the forwarder to the specifed value. 
	 * @param i the new forwarder value.
	 * @see #getForwarderChain()
	 */
	public void setForwarderChain(int i) {
		forwarderChain = i;
	}

	/**
	 * Sets the name to the specifed value. 
	 * @param i the new name value.
	 * @see #getName()
	 */
	public void setName(int i) {
		name = i;
	}

	/**
	 * Sets the first thunk to the specifed value. 
	 * @param i the new first thunk value.
	 * @see #getFirstThunk()
	 */
	public void setFirstThunk(int i) {
		firstThunk = i;
	}

	/**
	 * Checks to see if this descriptor is a null entry.  A null entry
	 * indicates that no more descriptors follow in the import table.
	 * 
	 * @return True if this descriptor is a null entry; otherwise, false.
	 */
	public boolean isNullEntry() {
		return characteristics == 0 && timeDateStamp == 0 && forwarderChain == 0 && name == 0 &&
			firstThunk == 0;
	}

}
