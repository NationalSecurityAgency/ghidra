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

public class Objc2Protocol extends ObjcTypeMetadataStructure {
	public final static String NAME = "protocol_t";

	private long isa;
	private String name;
	private Objc2ProtocolList protocols;
	private Objc2MethodList instanceMethods;
	private Objc2MethodList classMethods;

	private Objc2MethodList optionalInstanceMethods;
	private Objc2MethodList optionalClassMethods;
	private Objc2PropertyList instanceProperties;
	private long unknown0;
	private long unknown1;

	public Objc2Protocol(Program program, ObjcState state, BinaryReader reader) throws IOException {
		super(program, state, reader.getPointerIndex());

		isa = ObjcUtils.readNextIndex(reader, is32bit);//TODO
		readName(reader);
		readProtocols(reader);
		readInstanceMethods(reader);
		readClassMethods(reader);
		readOptionalInstanceMethods(reader);
		readOptionalClassMethods(reader);
		readInstanceProperties(reader);

		if (is32bit) {
			unknown0 = reader.readNextUnsignedInt();
			unknown1 = reader.readNextUnsignedInt();
		}
		else {
			unknown0 = reader.readNextLong();
			unknown1 = reader.readNextLong();
		}
	}

	public long getIsa() {
		return isa;
	}

	public String getName() {
		return name;
	}

	public Objc2ProtocolList getProtocols() {
		return protocols;
	}

	public Objc2MethodList getInstanceMethods() {
		return instanceMethods;
	}

	public Objc2MethodList getClassMethods() {
		return classMethods;
	}

	public Objc2MethodList getOptionalInstanceMethods() {
		return optionalInstanceMethods;
	}

	public Objc2MethodList getOptionalClassMethods() {
		return optionalClassMethods;
	}

	public Objc2PropertyList getInstanceProperties() {
		return instanceProperties;
	}

	public long getUnknown0() {
		return unknown0;
	}

	public long getUnknown1() {
		return unknown1;
	}

	public long getIndex() {
		return base;
	}

	private void readProtocols(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			protocols = new Objc2ProtocolList(program, state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readName(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			name = reader.readAsciiString(index);
		}
	}

	private void readInstanceMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			instanceMethods = new Objc2MethodList(program, state, reader, ObjcMethodType.INSTANCE);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readClassMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			classMethods = new Objc2MethodList(program, state, reader, ObjcMethodType.CLASS);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readOptionalInstanceMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			optionalInstanceMethods =
				new Objc2MethodList(program, state, reader, ObjcMethodType.INSTANCE);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readOptionalClassMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			optionalClassMethods =
				new Objc2MethodList(program, state, reader, ObjcMethodType.CLASS);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readInstanceProperties(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			instanceProperties = new Objc2PropertyList(program, state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);

		if (is32bit) {
			struct.add(DWORD, "isa", null);
		}
		else {
			struct.add(QWORD, "isa", null);
		}

		struct.add(new PointerDataType(STRING), pointerSize, "name", null);
		struct.add(new PointerDataType(Objc2ProtocolList.toGenericDataType(is32bit)),
			pointerSize, "protocols", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()), pointerSize,
			"instanceMethods", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()), pointerSize,
			"classMethods", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()), pointerSize,
			"optionalInstanceMethods", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()), pointerSize,
			"optionalClassMethods", null);
		struct.add(new PointerDataType(Objc2PropertyList.toGenericDataType()), pointerSize,
			"instanceProperties", null);

		if (is32bit) {
			struct.add(DWORD, "unknown0", null);
			struct.add(DWORD, "unknown1", null);
		}
		else {
			struct.add(QWORD, "unknown0", null);
			struct.add(QWORD, "unknown1", null);
		}

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
			Namespace protocolNamespace =
				ObjcUtils.createNamespace(program, Objc1Constants.NAMESPACE, Objc2Protocol.NAME);
			ObjcUtils.createSymbol(program, protocolNamespace, getName(), address);
		}
		catch (Exception e) {
			// do nothing
		}

		if (protocols != null) {
			protocols.applyTo(namespace, monitor);
		}
		if (instanceMethods != null) {
			instanceMethods.applyTo(namespace, monitor);
		}
		if (classMethods != null) {
			classMethods.applyTo(namespace, monitor);
		}
		if (optionalInstanceMethods != null) {
			optionalInstanceMethods.applyTo(namespace, monitor);
		}
		if (optionalClassMethods != null) {
			optionalClassMethods.applyTo(namespace, monitor);
		}
		if (instanceProperties != null) {
			instanceProperties.applyTo(namespace, monitor);
		}
	}
}
