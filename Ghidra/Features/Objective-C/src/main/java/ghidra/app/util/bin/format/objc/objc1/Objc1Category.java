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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc1Category extends ObjcTypeMetadataStructure {
	public static final long SIZEOF = 0;

	private String category_name;
	private String class_name;
	private Objc1MethodList instance_methods;
	private Objc1MethodList class_methods;
	private Objc1ProtocolList protocols;
	private int unknown0;
	private int unknown1;

	public Objc1Category(Program program, ObjcState state, BinaryReader reader) throws IOException {
		super(program, state, reader.getPointerIndex());

		category_name = reader.readAsciiString(reader.readNextInt());
		class_name = reader.readAsciiString(reader.readNextInt());
		instance_methods = new Objc1MethodList(program, state, reader.clone(reader.readNextInt()),
			ObjcMethodType.INSTANCE);
		class_methods = new Objc1MethodList(program, state, reader.clone(reader.readNextInt()),
			ObjcMethodType.CLASS);
		protocols = new Objc1ProtocolList(program, state, reader.clone(reader.readNextInt()));

		if (isArm) {
			unknown0 = reader.readNextInt();
			unknown1 = reader.readNextInt();
		}
	}

	public String getCategoryName() {
		return category_name;
	}

	public String getClassName() {
		return class_name;
	}

	public Objc1MethodList getInstanceMethods() {
		return instance_methods;
	}

	public Objc1MethodList getClassMethods() {
		return class_methods;
	}

	public Objc1ProtocolList getProtocols() {
		return protocols;
	}

	public int getUnknown0() {
		return unknown0;
	}

	public int getUnknown1() {
		return unknown1;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "objc_category";
		StructureDataType struct = new StructureDataType(name, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "category_name", null);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "class_name", null);
		struct.add(
			PointerDataType.getPointer(Objc1MethodList.toGenericDataType(pointerSize), pointerSize),
			"instance_methods", null);
		struct.add(
			PointerDataType.getPointer(Objc1MethodList.toGenericDataType(pointerSize), pointerSize),
			"class_methods", null);
		struct.add(PointerDataType.getPointer(Objc1ProtocolList.toGenericDataType(pointerSize),
			pointerSize), "protocols", null);
		if (isArm) {
			struct.add(DWORD, "unknown0", null);
			struct.add(DWORD, "unknown1", null);
		}
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		if (state.beenApplied.contains(base)) {
			return;
		}
		state.beenApplied.add(base);

		Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		DataType dt = toDataType();
		program.getListing().clearCodeUnits(address, address.add(dt.getLength() - 1), false);
		program.getListing().createData(address, dt);

		Namespace categoryNamespace = ObjcUtils.createNamespace(program, Objc1Constants.NAMESPACE,
			"Categories", class_name + '(' + category_name + ')');

		instance_methods.applyTo(categoryNamespace, monitor);
		class_methods.applyTo(categoryNamespace, monitor);
		protocols.applyTo(namespace, monitor);
	}
}
