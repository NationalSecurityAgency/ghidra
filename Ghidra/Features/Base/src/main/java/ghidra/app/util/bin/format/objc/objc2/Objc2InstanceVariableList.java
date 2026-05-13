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

public class Objc2InstanceVariableList extends ObjcTypeMetadataStructure {
	public final static String NAME = "ivar_list_t";

	private int entsize;
	private int count;
	private List<Objc2InstanceVariable> ivars = new ArrayList<Objc2InstanceVariable>();

	public Objc2InstanceVariableList(Program program, ObjcState state, BinaryReader reader)
			throws IOException {
		super(program, state, reader.getPointerIndex());

		entsize = reader.readNextInt();
		count = reader.readNextInt();

		for (int i = 0; i < count; ++i) {
			ivars.add(new Objc2InstanceVariable(program, state, reader));
		}
	}

	public long getEntsize() {
		return entsize;
	}

	public long getCount() {
		return count;
	}

	public List<Objc2InstanceVariable> getIvars() {
		return ivars;
	}

	public static DataType toGenericDataType() throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.add(DWORD, "entsize", null);
		struct.add(DWORD, "count", null);
		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME + '_' + count + '_', 0);

		struct.add(DWORD, "entsize", null);
		struct.add(DWORD, "count", null);

		for (int i = 0; i < ivars.size(); ++i) {
			struct.add(ivars.get(i).toDataType(), "var" + i, null);
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
			Namespace instanceVariableNamespace = ObjcUtils.createNamespace(program,
				Objc1Constants.NAMESPACE, Objc2InstanceVariableList.NAME);
			ObjcUtils.createSymbol(program, instanceVariableNamespace, namespace.getName(),
				address);
		}
		catch (Exception e) {
			// do nothing
		}

		for (Objc2InstanceVariable ivar : getIvars()) {
			ivar.applyTo(namespace, monitor);
		}
	}
}
