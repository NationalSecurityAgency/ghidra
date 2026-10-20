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
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc1Class extends ObjcTypeMetadataStructure {
	public final static String NAME = "objc_class";
	public static final long SIZEOF = 0x30;

	private Objc1MetaClass isa;
	private String super_class;
	private String name;
	private int version;
	private int info;
	private int instance_size;
	private Objc1InstanceVariableList variable_list;
	private Objc1MethodList method_list;
	private int cache;
	private Objc1ProtocolList protocols;
	private int unknown0;
	private int unknown1;

	public Objc1Class(Program program, ObjcState state, BinaryReader reader) throws IOException {
		super(program, state, reader.getPointerIndex());

		isa = new Objc1MetaClass(program, state, reader.clone(reader.readNextInt()));
		super_class = ObjcUtils.dereferenceAsciiString(reader, is32bit);
		name = reader.readAsciiString(reader.readNextInt());
		version = reader.readNextInt();
		info = reader.readNextInt();
		instance_size = reader.readNextInt();
		variable_list =
			new Objc1InstanceVariableList(program, state, reader.clone(reader.readNextInt()));
		method_list = new Objc1MethodList(program, state, reader.clone(reader.readNextInt()),
			ObjcMethodType.INSTANCE);
		cache = reader.readNextInt();
		protocols = new Objc1ProtocolList(program, state, reader.clone(reader.readNextInt()));
		unknown0 = reader.readNextInt();
		unknown1 = reader.readNextInt();
	}

	public Objc1MetaClass getISA() {
		return isa;
	}

	public String getSuperClass() {
		return super_class;
	}

	public String getName() {
		return name;
	}

	public int getVersion() {
		return version;
	}

	public int getInfo() {
		return info;
	}

	public int getInstanceSize() {
		return instance_size;
	}

	public Objc1InstanceVariableList getInstanceVariableList() {
		return variable_list;
	}

	public Objc1MethodList getMethodList() {
		return method_list;
	}

	public int getCache() {
		return cache;
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
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(isa.toDataType(), pointerSize), "isa", null);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "super_class", null);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "name", null);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "info", null);
		struct.add(DWORD, "instance_size", null);
		struct.add(PointerDataType.getPointer(Objc1InstanceVariableList.toGenericDataType(),
			pointerSize), "instance_vars", null);
		struct.add(PointerDataType.getPointer(Objc1MethodList.toGenericDataType(pointerSize),
			pointerSize), "method_lists", null);
		struct.add(DWORD, "cache", null);
		struct.add(PointerDataType.getPointer(Objc1ProtocolList.toGenericDataType(pointerSize),
			pointerSize), "protocols", null);
		struct.add(DWORD, "unknown0", null);
		struct.add(DWORD, "unknown1", null);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		DataType dt = toDataType();
		program.getListing().clearCodeUnits(address, address.add(dt.getLength() - 1), false);
		program.getListing().createData(address, dt);
		program.getSymbolTable().createLabel(address, "objc_class_" + name, SourceType.ANALYSIS);

		Namespace classNamespace = ObjcUtils.getClassNamespace(program, null, name);

		isa.applyTo(namespace, monitor);
		variable_list.applyTo(namespace, monitor);
		method_list.applyTo(classNamespace, monitor);

		//don't do protocols here... they are applied independent
	}
}
