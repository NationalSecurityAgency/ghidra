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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * <pre>
 * typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
 *     DWORD   OffsetToData;
 *     DWORD   Size;
 *     DWORD   CodePage;
 *     DWORD   Reserved;
 * };
 * </pre>
 */
public class ResourceDataEntry implements StructConverter {
	public final static String NAME = "IMAGE_RESOURCE_DATA_ENTRY";
	public final static int SIZEOF = 16;

    private int offsetToData;
    private int size;
    private int codePage;
    private int reserved;
	/**
	 * Constructor.
	 * @param reader the binary reader
	 * @param index the index where this entry begins
	 */
    public ResourceDataEntry(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        offsetToData = reader.readInt(index);
        size         = reader.readInt(index += BinaryReader.SIZEOF_INT);
        codePage     = reader.readInt(index += BinaryReader.SIZEOF_INT);
        reserved     = reader.readInt(index += BinaryReader.SIZEOF_INT);
    }
	/**
	 * Returns the offset, relative to the beginning of the resource
	 * directory of the data for the resource.
	 * @return the offset, relative to the beginning of the resource directory
	 */
    public int getOffsetToData() {
        return offsetToData;
    }
    /**
     * Returns a size field that gives the number of bytes of data at that offset.
     * @return a size field that gives the number of bytes of data at that offset,
     */
    public int getSize() {
        return size;
    }
    /**
     * @return a CodePage that should be used when decoding the resource data
     */
    public int getCodePage() {
        return codePage;
    }
    /**
     * Reserved, use unknown.
     * @return reserved, use unknown
     */
    public int getReserved() {
        return reserved;
    }

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(DWORD, "OffsetToData", null);
		struct.add(DWORD, "Size",         null);
		struct.add(DWORD, "CodePage",     null);
		struct.add(DWORD, "Reserved",     null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

    @Override
    public String toString() {
    	return "0x"+Integer.toHexString(offsetToData)+" - 0x"+Integer.toHexString(size);
    }
}
