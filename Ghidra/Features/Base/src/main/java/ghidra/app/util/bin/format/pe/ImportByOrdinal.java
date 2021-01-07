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
public class ImportByOrdinal implements StructConverter, ByteArrayConverter {
	public final static String NAME = "IMAGE_IMPORT_BY_ORDINAL";

	private long ordinal;

	static ImportByOrdinal createImportByOrdinal(
			FactoryBundledWithBinaryReader reader, int index)
			throws IOException {
		ImportByOrdinal importByOrdinal =
			(ImportByOrdinal) reader.getFactory().create(ImportByOrdinal.class);
		importByOrdinal.initImportByOrdinal(reader, index);
		return importByOrdinal;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ImportByOrdinal() {
	}

	private void initImportByOrdinal(FactoryBundledWithBinaryReader reader, int index)
			throws IOException {
		ordinal = reader.readLong(index);
	}

	/**
	 * @param hint the import hint (ordinal)
	 * @param name the name of the imported function.
	 */
	public ImportByOrdinal(long ordinal) {
		this.ordinal = ordinal;
	}

	/**
	 * @return the export ordinal for the imported function
	 */
	public long getHint() {
		return ordinal & 0xffff;
	}

	/**
	* @return the export ordinal for the imported function
	*/
	public long getOrdinal() {
		return ordinal;
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(DWORD, "Ordinal", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	public byte[] toBytes(DataConverter dc) {
		return dc.getBytes(ordinal);
	}

}
