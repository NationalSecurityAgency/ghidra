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
 * Represents a twolevel_hint structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class TwoLevelHint implements StructConverter {
	public final static int SIZEOF = 4;

	private int isub_image;
	private int itoc;

	static TwoLevelHint createTwoLevelHint(FactoryBundledWithBinaryReader reader)
			throws IOException {
		TwoLevelHint hint = (TwoLevelHint) reader.getFactory().create(TwoLevelHint.class);
		hint.initTwoLevelHint(reader);
		return hint;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public TwoLevelHint() {
	}

	private void initTwoLevelHint(FactoryBundledWithBinaryReader reader) throws IOException {
		int value = reader.readNextInt();

		isub_image = value & 0xff;
		itoc = (value >> 8);
	}

	/**
	 * An index into the sub-images (sub-frameworks and sub-umbrellas list).
	 * @return index into the sub-images
	 */
	public int getSubImageIndex() {
		return isub_image;
	}

	/**
	 * An index into the library's table of contents.
	 * @return index into the library's table of contents
	 */
	public int getTableOfContentsIndex() {
		return itoc;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("twolevel_hint", 0);
		struct.add(DWORD, "isub_image_itoc", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
