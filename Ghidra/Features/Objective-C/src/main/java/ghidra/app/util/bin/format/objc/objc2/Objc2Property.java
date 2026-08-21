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
package ghidra.app.util.bin.format.objc.objc2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc2Property extends ObjcTypeMetadataStructure {
	private String name;
	private String attributes;

	public Objc2Property(Program program, ObjcState state, BinaryReader reader) throws IOException {
		super(program, state, reader.getPointerIndex());

		long nameIndex = ObjcUtils.readNextIndex(reader, is32bit);
		name = reader.readAsciiString(nameIndex);

		long attributesIndex = ObjcUtils.readNextIndex(reader, is32bit);
		attributes = reader.readAsciiString(attributesIndex);
	}

	public String getName() {
		return name;
	}

	public String getAttributes() {
		return attributes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("objc_property", 0);

		struct.add(new PointerDataType(ASCII), pointerSize, "name", null);
		struct.add(new PointerDataType(ASCII), pointerSize, "name", null);

		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		// do nothing
	}
}
