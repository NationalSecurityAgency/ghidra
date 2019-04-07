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
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the 
 * <code>IMAGE_BOUND_FORWARDER_REF</code>
 * data structure defined in <b><code>winnt.h</code></b>.
 * <p>
 * <pre>
 * typedef struct _IMAGE_BOUND_FORWARDER_REF {
 *     DWORD   TimeDateStamp;
 *     WORD    OffsetModuleName;
 *     WORD    Reserved;
 * } IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;
 * </pre>
 */
public class BoundImportForwarderRef implements StructConverter, ByteArrayConverter {
	/**
	 * The name to use when converting into a structure data type.
	 */
    public final static String NAME = "IMAGE_BOUND_FORWARDER_REF";
	/**
	 * The size of the <code>IMAGE_BOUND_FORWARDER_REF</code> in bytes.
	 */
    public final static int IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF = 8;

    private int timeDateStamp;
    private short offsetModuleName;
    private short reserved;
    private String moduleName;

	/**
	 * 
	 * @param reader      the binary reader
	 * @param readerIndex the index into the binary reader
	 * @param biddIndex   the index where the bound import data directory begins
	 */
    static BoundImportForwarderRef createBoundImportForwarderRef(
            FactoryBundledWithBinaryReader reader, int readerIndex,
            int biddIndex) throws IOException {
        BoundImportForwarderRef boundImportForwarderRef = (BoundImportForwarderRef) reader.getFactory().create(BoundImportForwarderRef.class);
        boundImportForwarderRef.initBoundImportForwarderRef(reader, readerIndex, biddIndex);
        return boundImportForwarderRef;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public BoundImportForwarderRef() {}

    private void initBoundImportForwarderRef(FactoryBundledWithBinaryReader reader, int readerIndex, int biddIndex) throws IOException {
        timeDateStamp    = reader.readInt  (readerIndex); readerIndex += BinaryReader.SIZEOF_INT;
        offsetModuleName = reader.readShort(readerIndex); readerIndex += BinaryReader.SIZEOF_SHORT;
        reserved         = reader.readShort(readerIndex); readerIndex += BinaryReader.SIZEOF_SHORT;
        if (offsetModuleName < 0) {
        	Msg.error(this, "Invalid offsetModuleName "+Integer.toHexString(offsetModuleName));
        	return;
        }

        moduleName = reader.readAsciiString(biddIndex + offsetModuleName);
    }

    /**
     * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
     */
	public byte [] toBytes(DataConverter dc) {
		byte [] bytes = new byte[IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF];
		int pos = 0;
		dc.getBytes(timeDateStamp, bytes, pos);
		pos += BinaryReader.SIZEOF_INT;
		dc.getBytes(offsetModuleName, bytes, pos);
		pos += BinaryReader.SIZEOF_SHORT;
		dc.getBytes(reserved, bytes, pos);
		pos += BinaryReader.SIZEOF_SHORT;
		return bytes;
	}

	/**
	 * Returns the time stamp.
	 * @return the time stamp
	 */
    public int getTimeDateStamp() {
        return timeDateStamp;
    }

	/**
	 * Returns the offset, relative the beginning of the Bound Import Table,
	 * to the import name.
	 * @return the offset to the import name
	 */
    public short getOffsetModuleName() {
        return offsetModuleName;
    }

	void setOffsetModuleName(short offset) {
		this.offsetModuleName = offset;
	}

	/**
	 * Returns the reserved word (use unknown).
	 * @return the reserved word
	 */
    public short getReserved() {
        return reserved;
    }

	/**
	 * Returns the imported module name.
	 * @return the imported module name
	 */
    public String getModuleName() {
        return moduleName;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME, 0);

        struct.add(DWORD,"TimeDateStamp",null);
        struct.add(WORD,"OffsetModuleName",null);
        struct.add(WORD,"Reserved",null);

        struct.setCategoryPath(new CategoryPath("/PE"));

        return struct;
    }
}
