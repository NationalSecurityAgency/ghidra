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
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the 
 * <code>IMAGE_BOUND_IMPORT_DESCRIPTOR</code>
 * data structure defined in <b><code>winnt.h</code></b>.
 * <p>
 * <pre>
 * typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
 *     DWORD   TimeDateStamp;
 *     WORD    OffsetModuleName;
 *     WORD    NumberOfModuleForwarderRefs;
 *     // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
 * } IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;
 * </pre>
 */
public class BoundImportDescriptor implements StructConverter, ByteArrayConverter {
	/**
	 * The name to use when converting into a structure data type.
	 */
    public final static String NAME = "IMAGE_BOUND_IMPORT_DESCRIPTOR";
	/**
	 * The size of the <code>IMAGE_BOUND_IMPORT_DESCRIPTOR</code> in bytes.
	 */
    public final static int IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR = 8;

    private String moduleName;
    private int    timeDateStamp;
    private short  offsetModuleName;
    private short  numberOfModuleForwarderRefs;

    private List<BoundImportForwarderRef> forwarders = new ArrayList<BoundImportForwarderRef>();

    static BoundImportDescriptor createBoundImportDescriptor(
            FactoryBundledWithBinaryReader reader, int readerIndex,
            int biddIndex) throws IOException {
        BoundImportDescriptor boundImportDescriptor = (BoundImportDescriptor) reader.getFactory().create(BoundImportDescriptor.class);
        boundImportDescriptor.initBoundImportDescriptor(reader, readerIndex, biddIndex);
        return boundImportDescriptor;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public BoundImportDescriptor() {}

    private void initBoundImportDescriptor(FactoryBundledWithBinaryReader reader, int readerIndex, int biddIndex) throws IOException {
        timeDateStamp               = reader.readInt  (readerIndex); readerIndex += BinaryReader.SIZEOF_INT;
        offsetModuleName            = reader.readShort(readerIndex); readerIndex += BinaryReader.SIZEOF_SHORT;
        numberOfModuleForwarderRefs = reader.readShort(readerIndex); readerIndex += BinaryReader.SIZEOF_SHORT;
        if (offsetModuleName < 0) {
        	Msg.error(this, "Invalid offsetModuleName "+offsetModuleName);
        	return;
        }

        moduleName = reader.readAsciiString(biddIndex + offsetModuleName);

        for (int i = 0 ; i < numberOfModuleForwarderRefs ; ++i) {
            forwarders.add(BoundImportForwarderRef.createBoundImportForwarderRef(reader, readerIndex, biddIndex));
            readerIndex += BoundImportForwarderRef.IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF;
        }
    }

	public BoundImportDescriptor(String name, int timeDateStamp) {
		this.moduleName = name;
		this.timeDateStamp = timeDateStamp;
	}

	/**
	 * Returns the time/data stamp of the imported DLL.
	 * @return the time/data stamp of the imported DLL
	 */
    public int getTimeDateStamp() {
        return timeDateStamp;
    }

	/**
	 * Returns an offset to a string with the name of the imported DLL. 
	 * @return an offset to a string with the name
	 */
    public short getOffsetModuleName() {
        return offsetModuleName;
    }

	void setOffsetModuleName(short offset) {
		this.offsetModuleName = offset;
	}

	/**
	 * Returns the number of IMAGE_BOUND_FORWARDER_REF 
	 * structures that immediately follow this structure. 
	 * @return the number of IMAGE_BOUND_FORWARDER_REF structures that immediately follow this structure
	 */
    public short getNumberOfModuleForwarderRefs() {
        return numberOfModuleForwarderRefs;
    }

	/**
	 * Returns the module name of the imported DLL.
	 * @return the module name of the imported DLL
	 */
    public String getModuleName() {
        return moduleName;
    }

	/**
	 * Returns the forwarder ref at the specified index
	 * @param index the index of the forwarder ref
	 * @return the forwarder ref at the specified index
	 */
    public BoundImportForwarderRef getBoundImportForwarderRef(int index) {
    	if (index >= forwarders.size()) {
    		return null;
    	}
        return forwarders.get(index);
    }

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("TimeStamp:"+Integer.toHexString(timeDateStamp)+",");
		buffer.append("OffsetModuleName:"+Integer.toHexString(Conv.shortToInt(offsetModuleName))+"["+moduleName+"]"+",");
		buffer.append("NumberOfModuleForwarderRefs:"+Integer.toHexString(Conv.shortToInt(numberOfModuleForwarderRefs)));
		buffer.append("\n");
		for(int i=0;i<forwarders.size();i++) {
			BoundImportForwarderRef ref = forwarders.get(i);
			buffer.append("\t"+"TimeStamp:"+Integer.toHexString(ref.getTimeDateStamp())+",");
			buffer.append("\t"+"OffsetModuleName:"+Integer.toHexString(Conv.shortToInt(ref.getOffsetModuleName()))+"["+ref.getModuleName()+"]"+",");
			buffer.append("\t"+"Reserved:"+Integer.toHexString(Conv.shortToInt(ref.getReserved())));
			buffer.append("\n");
		}
		return buffer.toString();
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME+"_"+forwarders.size(), 0);

        struct.add(DWORD,"TimeDateStamp",null);
        struct.add( WORD,"OffsetModuleName",null);
        struct.add( WORD,"NumberOfModuleForwarderRefs",null);

        for(int i=0;i<forwarders.size();i++) {
            BoundImportForwarderRef ref = forwarders.get(i);
            struct.add(ref.toDataType());
		}

        struct.setCategoryPath(new CategoryPath("/PE"));

        return struct;
    }

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	public byte [] toBytes(DataConverter dc) {
		byte [] bytes = new byte[IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR + 
			(numberOfModuleForwarderRefs*BoundImportForwarderRef.IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF)];
		int pos = 0;
		dc.getBytes(timeDateStamp, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;
		dc.getBytes(offsetModuleName, bytes, pos);
		pos += BinaryReader.SIZEOF_SHORT;
		dc.getBytes(numberOfModuleForwarderRefs, bytes, pos);
		pos += BinaryReader.SIZEOF_SHORT;
		for (int i = 0; i < numberOfModuleForwarderRefs; i++) {
			byte [] refBytes = forwarders.get(i).toBytes(dc);
			System.arraycopy(refBytes, 0, bytes, pos, refBytes.length);
			pos += refBytes.length;
		}
		return bytes;
	}
}
