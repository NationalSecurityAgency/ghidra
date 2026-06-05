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
package ghidra.app.util.bin.format.objc;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public abstract class ObjcMethodList extends ObjcTypeMetadataStructure {
	private String _className;

	protected List<ObjcMethod> methods = new ArrayList<ObjcMethod>();

	protected ObjcMethodList(Program program, ObjcState state, BinaryReader reader,
			String className) {
		super(program, state, reader.getPointerIndex());
		this._className = className;
	}

	public List<ObjcMethod> getMethods() {
		return methods;
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

		Address address = ObjcUtils.toAddress(program, base);
		DataType dt = toDataType();
		try {
			ObjcUtils.createData(program, dt, address);
		}
		catch (Exception e) {
			Msg.warn(this, "Could not create " + dt.getName() + " @" + address);
		}

		try {
			//creates a symbol on the method list data structure
			Namespace methodListNamespace =
				ObjcUtils.createNamespace(program, Objc1Constants.NAMESPACE, _className);
			ObjcUtils.createSymbol(program, methodListNamespace, namespace.getName(), address);
		}
		catch (Exception e) {
			// do nothing
		}

		for (ObjcMethod method : getMethods()) {
			method.applyTo(namespace, monitor);
		}
	}

}
