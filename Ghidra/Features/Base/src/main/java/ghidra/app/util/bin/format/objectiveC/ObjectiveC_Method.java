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

public abstract class ObjectiveC_Method implements StructConverter {
	protected ObjectiveC1_State _state;
	protected long _index;
	protected ObjectiveC_MethodType _methodType;

	protected ObjectiveC_Method(ObjectiveC1_State state, BinaryReader reader, ObjectiveC_MethodType methodType) {
		this._state = state;
		this._index = reader.getPointerIndex();
		this._methodType = methodType;
	}

	public final long getIndex() {
		return _index;
	}

	public final ObjectiveC_MethodType getMethodType() {
		return _methodType;
	}

	public abstract String getName();

	public abstract String getTypes();

	public abstract long getImplementation();

	public void applyTo(Namespace namespace) throws Exception {
		long implementation = getImplementation();

		if (implementation == 0) {
			return;
		}
		if (getName() == null && getName().length() == 0) {
			return;
		}

		boolean isThumbCode = ObjectiveC1_Utilities.isThumb(_state.program, implementation);

		if (isThumbCode) {
			implementation -= 1;
		}

		Address implementationAddress = _state.program.getAddressFactory().getDefaultAddressSpace().getAddress(implementation);
		ObjectiveC1_Utilities.createSymbol(_state.program, namespace, getName(), implementationAddress);
		_state.methodMap.put(implementationAddress, this);

		if (isThumbCode) {
			_state.thumbCodeLocations.add(implementationAddress);
		}
	}
}
