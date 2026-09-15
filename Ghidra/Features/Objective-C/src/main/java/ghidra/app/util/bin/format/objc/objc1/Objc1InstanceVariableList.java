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

public class Objc1InstanceVariableList extends ObjcTypeMetadataStructure {
	public static final String NAME = "objc_method_list";

	private int ivar_count;
	private List<Objc1InstanceVariable> ivar_list = new ArrayList<Objc1InstanceVariable>();

	Objc1InstanceVariableList(Program program, ObjcState state, BinaryReader reader)
			throws IOException {
		super(program, state, reader.getPointerIndex());
		if (base == 0) {
			return;
		}

		ivar_count = reader.readNextInt();

		for (int i = 0 ; i < ivar_count ; ++i) {
			ivar_list.add(new Objc1InstanceVariable(program, state, reader));
		}
	}

	public int getInstanceVariableCount() {
		return ivar_count;
	}

	public List<Objc1InstanceVariable> getInstanceVariables() {
		return ivar_list;
	}

	public static DataType toGenericDataType() throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(DWORD, "ivar_count", null);
		return struct;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("objc_ivar_list"+"_"+ivar_count+"_", 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(DWORD, "ivar_count", null);
		if (ivar_count > 0) {
			DataType dt = ivar_list.get(0).toDataType();
			struct.add(new ArrayDataType(dt, ivar_count, dt.getLength()), "ivar_list", null);
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
	}
}
