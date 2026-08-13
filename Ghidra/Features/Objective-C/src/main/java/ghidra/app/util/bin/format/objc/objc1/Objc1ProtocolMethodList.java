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
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc1ProtocolMethodList extends ObjcTypeMetadataStructure {
	public static final String NAME = "objc_protocol_method_list";

	private int method_count;
	private List<Objc1ProtocolMethod> method_list = new ArrayList<Objc1ProtocolMethod>();

	Objc1ProtocolMethodList(Program program, ObjcState state, BinaryReader reader,
			ObjcMethodType methodType) throws IOException {
		super(program, state, reader.getPointerIndex());
		if (base == 0) {
			return;
		}

		method_count = reader.readNextInt();

		for (int i = 0 ; i < method_count ; ++i) {
			method_list.add(new Objc1ProtocolMethod(program, state, reader, methodType));
		}
	}

	public int getMethodCount() {
		return method_count;
	}

	public List<Objc1ProtocolMethod> getMethodList() {
		return method_list;
	}

	public static DataType toGenericDataType(ObjcState state)
			throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(DWORD, "method_count", null);
		return struct;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME+"_"+method_count+"_", 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(DWORD, "method_count", null);
		if (method_count > 0) {
			DataType dt = method_list.get(0).toDataType();
			struct.add(new ArrayDataType(dt, method_count, dt.getLength()), "method_list", null);
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

		for (Objc1ProtocolMethod method : method_list) {
			if (monitor.isCancelled()) {
				break;
			}
			method.applyTo(namespace, monitor);
		}
	}

}
