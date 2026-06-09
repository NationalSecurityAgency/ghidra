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

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.TaskMonitor;

public abstract class ObjcMethod extends ObjcTypeMetadataStructure {
	protected ObjcMethodType _methodType;

	public ObjcMethod(Program program, ObjcState state, BinaryReader reader,
			ObjcMethodType methodType) {
		super(program, state, reader.getPointerIndex());
		this._methodType = methodType;
	}

	public final ObjcMethodType getMethodType() {
		return _methodType;
	}

	public abstract String getName();

	public abstract String getTypes();

	public abstract long getImplementation();

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		long implementation = getImplementation();

		if (implementation == 0) {
			return;
		}
		if (getName() == null || getName().length() == 0) {
			return;
		}

		boolean isThumbCode = ObjcUtils.isThumb(program, implementation);

		if (isThumbCode) {
			implementation -= 1;
		}

		Address implementationAddress =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(implementation);
		ObjcUtils.createSymbol(program, namespace, getName(), implementationAddress);
		state.methodMap.put(implementationAddress, this);

		if (isThumbCode) {
			state.thumbCodeLocations.add(implementationAddress);
		}
	}
}
