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

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.*;

import java.io.*;

/**
 * A class to represent the <code>IMAGE_IMPORT_BY_NAME</code>
 * data structure defined in <b><code>winnt.h</code></b>.
 *
 * <pre>
 * typedef struct _IMAGE_IMPORT_BY_NAME {
 *     WORD    Hint;
 *     BYTE    Name[1];
 * };
 * </pre>
 * 
 * 
 */
public class ImportByName implements StructConverter, ByteArrayConverter {
	public final static String NAME = "IMAGE_IMPORT_BY_NAME";

    private short  hint;
    private String name;

    static ImportByName createImportByName(
            FactoryBundledWithBinaryReader reader, int index)
            throws IOException {
        ImportByName importByName = (ImportByName) reader.getFactory().create(ImportByName.class);
        importByName.initImportByName(reader, index);
        return importByName;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public ImportByName() {}

	private void initImportByName(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        hint = reader.readShort(index);
        name = reader.readAsciiString(index+BinaryReader.SIZEOF_SHORT);
    }

	/**
	 * @param hint the import hint (ordinal)
	 * @param name the name of the imported function.
	 */
	public ImportByName(short hint, String name) {
		this.hint = hint;
		this.name = name;
	}

    /**
     * @return the export ordinal for the imported function
     */
	public short getHint() {
        return hint;
    }

    /**
     * Returns an ASCIIZ string with the name of the imported function.
     * @return an ASCIIZ string with the name of the imported function
     */
	public String getName() {
        return name;
    }

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		int len = name.length()+1;
		StructureDataType struct = new StructureDataType(NAME+"_"+len, 0);
		struct.add(WORD, "Hint", null);
		struct.add(STRING, len, "Name", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	public byte [] toBytes(DataConverter dc) {
		byte [] bytes = new byte[getSizeOf()];
		dc.getBytes(hint, bytes, 0);
		byte [] nameBytes = name.getBytes();
		System.arraycopy(nameBytes, 0, bytes, 2, nameBytes.length);
		return bytes;
	}

	/**
	 * Returns the actual number of bytes consumed by this structure in memory.
	 * @return the actual number of bytes consumed by this structure in memory
	 */
	public int getSizeOf() {
		return BinaryReader.SIZEOF_SHORT+name.length()+1;
	}
}
