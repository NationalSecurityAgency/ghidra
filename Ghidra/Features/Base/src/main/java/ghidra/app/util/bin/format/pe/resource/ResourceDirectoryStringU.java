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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * <pre>
 * typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
 *     WORD    Length;
 *     WCHAR   NameString[ 1 ];
 * };
 * </pre>
 */
public class ResourceDirectoryStringU implements StructConverter {
	public final static String NAME = "IMAGE_RESOURCE_DIR_STRING_U";

    private short  length;
    private String nameString;

    /**
	 * Constructor.
	 * @param reader the binary reader
	 * @param index the index where this resource string begins
	 */
    public ResourceDirectoryStringU(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        length = reader.readShort(index);
        nameString = reader.readUnicodeString(index+BinaryReader.SIZEOF_SHORT, length);
    }

    /**
	 * Returns the length of the string, in bytes.
	 * @return the length of the string, in bytes
	 */
    public short getLength() {
        return length;
    }

    /**
	 * Returns the resource name string.
	 * @return the resource name string
	 */
    public String getNameString() {
        return nameString;
    }

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME+"_"+(length*2), 0);
		struct.add(WORD, "Length", null);
		struct.add(UTF16, length*2, "NameString", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

    @Override
    public String toString() {
    	return nameString;
    }
}
