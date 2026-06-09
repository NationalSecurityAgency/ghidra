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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.*;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc2ProtocolList extends ObjcTypeMetadataStructure {
	public final static String NAME = "protocol_list_t";

	private List<Objc2Protocol> protocols = new ArrayList<Objc2Protocol>();

	public Objc2ProtocolList(Program program, ObjcState state, BinaryReader reader)
			throws IOException {
		super(program, state, reader.getPointerIndex());

		long count = is32bit ? reader.readNextUnsignedInt() : reader.readNextLong();

		for (long i = 0; i < count; ++i) {
			long protocolIndex = ObjcUtils.readNextIndex(reader, is32bit);
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(protocolIndex);
			protocols.add(new Objc2Protocol(program, state, reader));
			reader.setPointerIndex(originalIndex);
		}
	}

	public long getCount() {
		return protocols.size();
	}

	public List<Objc2Protocol> getProtocols() {
		return protocols;
	}

	public static DataType toGenericDataType(boolean is32bit)
			throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		if (is32bit) {
			struct.add(DWORD, "count", null);
		}
		else {
			struct.add(QWORD, "count", null);
		}
		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME + '_' + protocols.size() + '_', 0);

		if (is32bit) {
			struct.add(DWORD, "count", null);
		}
		else {
			struct.add(QWORD, "count", null);
		}

		for (int i = 0; i < protocols.size(); ++i) {
			DataType dataType = protocols.get(i).toDataType();
			struct.add(new PointerDataType(dataType), pointerSize, "protocol" + i, null);
		}

		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		Address address = ObjcUtils.toAddress(program, base);
		try {
			ObjcUtils.createData(program, toDataType(), address);
		}
		catch (Exception e) {
			// do nothing
		}

		try {
			Namespace protocolListNamespace = ObjcUtils.createNamespace(program,
				Objc1Constants.NAMESPACE, Objc2ProtocolList.NAME);
			ObjcUtils.createSymbol(program, protocolListNamespace, namespace.getName(), address);
		}
		catch (Exception e) {
			// do nothing
		}

		for (Objc2Protocol protocol : getProtocols()) {
			protocol.applyTo(namespace, monitor);
		}
	}
}
