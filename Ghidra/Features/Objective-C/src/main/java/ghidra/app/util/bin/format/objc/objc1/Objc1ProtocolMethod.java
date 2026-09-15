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
package ghidra.app.util.bin.format.objc.objc1;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc1ProtocolMethod extends ObjcTypeMetadataStructure {
	private static final String NAME = "objc_protocol_method";

	private ObjcMethodType _methodType;

	private String name;
	private String types;

	Objc1ProtocolMethod(Program program, ObjcState state, BinaryReader reader,
			ObjcMethodType methodType) throws IOException {
		super(program, state, reader.getPointerIndex());
		this._methodType = methodType;

		name = ObjcUtils.dereferenceAsciiString(reader, is32bit);
		types = ObjcUtils.dereferenceAsciiString(reader, is32bit);
	}

	public String getName() {
		return name;
	}

	public String getTypes() {
		return types;
	}

	public ObjcMethodType getMethodType() {
		return _methodType;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "name", null);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "types", null);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		// do nothing
	}
}
