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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dylib_table_of_contents structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class TableOfContents implements StructConverter {
	private int symbol_index;
	private int module_index;

	static TableOfContents createTableOfContents(FactoryBundledWithBinaryReader reader)
			throws IOException {
		TableOfContents tableOfContents =
			(TableOfContents) reader.getFactory().create(TableOfContents.class);
		tableOfContents.initTableOfContents(reader);
		return tableOfContents;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public TableOfContents() {
	}

	private void initTableOfContents(FactoryBundledWithBinaryReader reader) throws IOException {
		symbol_index = reader.readNextInt();
		module_index = reader.readNextInt();
	}

	/**
	 * An index into the symbol table indicating the defined external symbols
	 * to which this entry refers.
	 * @return an index into the symbol table
	 */
	public int getSymbolIndex() {
		return symbol_index;
	}

	/**
	 * An index into the module table indicating the module in which this defined
	 * external symbol is defined.
	 * @return an index into the module table
	 */
	public int getModuleIndex() {
		return module_index;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dylib_table_of_contents", 0);
		struct.add(DWORD, "symbol_index", null);
		struct.add(DWORD, "module_index", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
