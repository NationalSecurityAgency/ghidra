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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc2MessageReference extends ObjcTypeMetadataStructure {
	public static final String NAME = "message_ref";

	public static int SIZEOF(int pointerSize) {
		return 2 * pointerSize;
	}

	private long implementation;
	private String selector;

	public Objc2MessageReference(Program program, ObjcState state, BinaryReader reader)
			throws IOException {
		super(program, state, reader.getPointerIndex());

		if (is32bit) {
			implementation = reader.readNextUnsignedInt();
		}
		else {
			implementation = reader.readNextLong();
		}

		long selectorIndex = ObjcUtils.readNextIndex(reader, is32bit);
		if (selectorIndex != 0) {
			selector = reader.readAsciiString(selectorIndex);
		}
	}

	public long getImplementation() {
		return implementation;
	}

	public String getSelector() {
		return selector;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		Address address = ObjcUtils.toAddress(program, base);
		DataType dt = toDataType();
		Data messageRefData = program.getListing().createData(address, dt);
		Data selData = messageRefData.getComponent(1);
		Object selAddress = selData.getValue();
		Data selStringData = program.getListing().getDataAt((Address) selAddress);
		Object selString = selStringData.getValue();
		ObjcUtils.createSymbol(program, null, selString + "_" + Objc2MessageReference.NAME,
			address);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.add(new PointerDataType(VOID), pointerSize, "imp", null);
		struct.add(new PointerDataType(ASCII), pointerSize, "sel", null);
		return struct;
	}
}
