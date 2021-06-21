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
package ghidra.pcode.exec;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.Varnode;

public interface PcodeExecutorStatePiece<A, T> {

	A longToOffset(AddressSpace space, long l);

	default void setVar(Register reg, T val) {
		Address address = reg.getAddress();
		setVar(address.getAddressSpace(), address.getOffset(), reg.getMinimumByteSize(), true, val);
	}

	default void setVar(Varnode var, T val) {
		Address address = var.getAddress();
		setVar(address.getAddressSpace(), address.getOffset(), var.getSize(), true, val);
	}

	void setVar(AddressSpace space, A offset, int size, boolean truncateAddressableUnit, T val);

	default void setVar(AddressSpace space, long offset, int size, boolean truncateAddressableUnit,
			T val) {
		setVar(space, longToOffset(space, offset), size, truncateAddressableUnit, val);
	}

	default T getVar(Register reg) {
		Address address = reg.getAddress();
		return getVar(address.getAddressSpace(), address.getOffset(), reg.getMinimumByteSize(),
			true);
	}

	default T getVar(Varnode var) {
		Address address = var.getAddress();
		return getVar(address.getAddressSpace(), address.getOffset(), var.getSize(), true);
	}

	T getVar(AddressSpace space, A offset, int size, boolean truncateAddressableUnit);

	default T getVar(AddressSpace space, long offset, int size, boolean truncateAddressableUnit) {
		return getVar(space, longToOffset(space, offset), size, truncateAddressableUnit);
	}

	MemBuffer getConcreteBuffer(Address address);

	default long truncateOffset(AddressSpace space, long offset) {
		return space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();
	}
}
