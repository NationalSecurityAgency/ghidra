/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.objectiveC;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;

import java.util.ArrayList;
import java.util.List;

public abstract class ObjectiveC_MethodList implements StructConverter {
	private String _className;
	protected ObjectiveC1_State _state;
	protected long _index = -1;

	protected List<ObjectiveC_Method> methods = new ArrayList<ObjectiveC_Method>();

	protected ObjectiveC_MethodList(ObjectiveC1_State state, BinaryReader reader, String className) {
		this._state = state;
		this._index = reader.getPointerIndex();
		this._className = className;
	}

	public List<ObjectiveC_Method> getMethods() {
		return methods;
	}

	public void applyTo(Namespace namespace) throws Exception {
		if (_index == 0) {
			return;
		}
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address = ObjectiveC1_Utilities.toAddress(_state.program, _index);
		try {
			ObjectiveC1_Utilities.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {}

		try {
			//creates a symbol on the method list data structure
			Namespace methodListNamespace = ObjectiveC1_Utilities.createNamespace(_state.program, ObjectiveC1_Constants.NAMESPACE, _className);
			ObjectiveC1_Utilities.createSymbol(_state.program, methodListNamespace, namespace.getName(), address);
		}
		catch (Exception e) {}

		for (ObjectiveC_Method method : getMethods()) {
			method.applyTo(namespace);
		}
	}

}
