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
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc2ClassRW extends ObjcTypeMetadataStructure {
	public final static String NAME = "class_rw_t";

	private long flags;
	private long instanceStart;
	private long instanceSize;
	private long reserved;
	private String name;
	private Objc2MethodList baseMethods;
	private Objc2ProtocolList baseProtocols;
	private Objc2InstanceVariableList ivars;
	private long weakIvarLayout;
	private Objc2PropertyList baseProperties;

	public Objc2ClassRW(Program program, ObjcState state) {
		super(program, state, -1);
	}

	public Objc2ClassRW(Program program, ObjcState state, BinaryReader reader) throws IOException {
		super(program, state, reader.getPointerIndex());

		if (is32bit) {
			flags = reader.readNextUnsignedInt();
			instanceStart = reader.readNextUnsignedInt();
			instanceSize = reader.readNextUnsignedInt();
			reserved = reader.readNextUnsignedInt();
		}
		else {
			flags = reader.readNextLong();
			instanceStart = reader.readNextLong();
			instanceSize = reader.readNextLong();
		}

		readName(reader);
		readBaseMethods(reader);
		readBaseProtocols(reader);
		readInstanceVariables(reader);

		weakIvarLayout = ObjcUtils.readNextIndex(reader, is32bit);

		readBaseProperties(reader);
	}

	public long getIndex() {
		return base;
	}

	public String getName() {
		return name;
	}

	public long getFlags() {
		return flags;
	}

	public long getInstanceStart() {
		return instanceStart;
	}

	public long getInstanceSize() {
		return instanceSize;
	}

	public long getReserved() {
		return reserved;
	}

	public long getWeakIvarLayout() {
		return weakIvarLayout;
	}

	public Objc2MethodList getBaseMethods() {
		return baseMethods;
	}

	public Objc2ProtocolList getBaseProtocols() {
		return baseProtocols;
	}

	public Objc2InstanceVariableList getInstanceVariables() {
		return ivars;
	}

	public Objc2PropertyList getBaseProperties() {
		return baseProperties;
	}

	private void readName(BinaryReader reader) throws IOException {
		long nameIndex = ObjcUtils.readNextIndex(reader, is32bit);
		if (nameIndex != 0) {
			name = reader.readAsciiString(nameIndex);
		}
	}

	private void readBaseProperties(BinaryReader reader) throws IOException {
		long propertiesIndex = ObjcUtils.readNextIndex(reader, is32bit);
		if (propertiesIndex != 0) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(propertiesIndex);
			baseProperties = new Objc2PropertyList(program, state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readInstanceVariables(BinaryReader reader)
			throws IOException {
		long instanceVariablesIndex = ObjcUtils.readNextIndex(reader, is32bit);
		if (instanceVariablesIndex != 0) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(instanceVariablesIndex);
			ivars = new Objc2InstanceVariableList(program, state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readBaseProtocols(BinaryReader reader) throws IOException {
		long protocolsIndex = ObjcUtils.readNextIndex(reader, is32bit);
		if (protocolsIndex != 0) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(protocolsIndex);
			baseProtocols = new Objc2ProtocolList(program, state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readBaseMethods(BinaryReader reader) throws IOException {
		long methodsIndex = ObjcUtils.readNextIndex(reader, is32bit);
		if (methodsIndex != 0) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(methodsIndex);
			baseMethods = new Objc2MethodList(program, state, reader, ObjcMethodType.INSTANCE);
			reader.setPointerIndex(originalIndex);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);

		if (is32bit) {
			struct.add(DWORD, "flags", null);
			struct.add(DWORD, "instanceStart", null);
			struct.add(DWORD, "instanceSize", null);
			struct.add(DWORD, "reserved", null);
		}
		else {
			struct.add(QWORD, "flags", null);
			struct.add(QWORD, "instanceStart", null);
			struct.add(QWORD, "instanceSize", null);
		}

		struct.add(new PointerDataType(ASCII), pointerSize, "name", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()), pointerSize,
			"baseMethods", null);
		struct.add(new PointerDataType(Objc2ProtocolList.toGenericDataType(is32bit)), pointerSize,
			"baseProtocols", null);
		struct.add(new PointerDataType(Objc2InstanceVariableList.toGenericDataType()), pointerSize,
			"ivars", null);

		if (is32bit) {
			struct.add(DWORD, "weakIvarLayout", null);
		}
		else {
			struct.add(QWORD, "weakIvarLayout", null);
		}

		struct.add(new PointerDataType(Objc2PropertyList.toGenericDataType()), pointerSize,
			"baseProperties", null);

		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		Address address = ObjcUtils.toAddress(program, getIndex());

		try {
			ObjcUtils.createData(program, toDataType(), address);
		}
		catch (Exception e) {
			// do nothing
		}

		try {
			Namespace classNamespace = ObjcUtils.createNamespace(program, Objc1Constants.NAMESPACE,
				Objc2ClassRW.NAME);
			ObjcUtils.createSymbol(program, classNamespace, getName(), address);
		}
		catch (Exception e) {
			// do nothing
		}

		Namespace classNamespace = ObjcUtils.getClassNamespace(program, null, getName());

		if (baseMethods != null) {
			baseMethods.applyTo(classNamespace, monitor);
		}
		if (baseProtocols != null) {
			baseProtocols.applyTo(classNamespace, monitor);
		}
		if (ivars != null) {
			ivars.applyTo(classNamespace, monitor);
		}
		if (baseProperties != null) {
			baseProperties.applyTo(classNamespace, monitor);
		}
	}
}
