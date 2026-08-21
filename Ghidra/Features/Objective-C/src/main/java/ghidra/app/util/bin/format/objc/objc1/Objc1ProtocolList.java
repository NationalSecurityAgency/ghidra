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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.ObjcState;
import ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc1ProtocolList extends ObjcTypeMetadataStructure {
	public static final String NAME = "objc_protocol_list";

	private Objc1ProtocolList next;
	private int count;
	private List<Objc1Protocol> protocols = new ArrayList<Objc1Protocol>();

	Objc1ProtocolList(Program program, ObjcState state, BinaryReader reader) throws IOException {
		super(program, state, reader.getPointerIndex());
		if (base == 0) {
			return;
		}

		next = new Objc1ProtocolList(program, state, reader.clone(reader.readNextInt()));

		count = reader.readNextInt();

		for (int i = 0 ; i < count ; ++i) {
			int protocolIndex = reader.readNextInt();
			long oldProtocolIndex = reader.getPointerIndex();
			reader.setPointerIndex(protocolIndex);
			protocols.add(new Objc1Protocol(program, state, reader));
			reader.setPointerIndex(oldProtocolIndex);
		}
	}

	public Objc1ProtocolList getNext() {
		return next;
	}

	public int getCount() {
		return count;
	}

	public List<Objc1Protocol> getProtocols() {
		return protocols;
	}

	public static DataType toGenericDataType(int pointerSize) throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(struct, pointerSize), "next", null);
		struct.add(DWORD, "count", null);
		return struct;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME+"_"+count+"_", 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(toGenericDataType(pointerSize), pointerSize), "next",
			null);
		struct.add(DWORD, "count", null);
		if (count > 0) {
			DataType dt =
				PointerDataType.getPointer(protocols.get(0).toDataType(), pointerSize);
			struct.add(new ArrayDataType(dt, count, dt.getLength()), "protocols", null);
		}
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		if (base == 0) {
			return;
		}
		if (state.beenApplied.contains(base)) {
			return;
		}
		state.beenApplied.add(base);

		Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		DataType dt = toDataType();
		program.getListing().clearCodeUnits(address, address.add(dt.getLength() - 1), false);
		program.getListing().createData(address, dt);

		for (Objc1Protocol protocol : protocols) {
			if (monitor.isCancelled()) {
				break;
			}
			protocol.applyTo(namespace, monitor);
		}
	}
}
