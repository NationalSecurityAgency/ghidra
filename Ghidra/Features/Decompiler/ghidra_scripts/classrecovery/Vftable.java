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
package classrecovery;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;

public class Vftable {
	
	private Address vftableAddress;
	private Namespace namespace;
	private Vtable vtable;
	private RecoveredClass containingClass;
	private Long classOffset;
	private RecoveredClass associatedClass;
	private boolean isInternal;
	private List<Address> vfunctions = new ArrayList<Address>();
	
	public Vftable(Address vttAddress, Namespace namespace, Vtable vtable, boolean isInternal) {
		this.vftableAddress = vttAddress;
		this.namespace = namespace;
		this.vtable = vtable;
		this.isInternal = isInternal;
	}
	
	public Address getAddress() {
		return vftableAddress;
	}
	
	public Namespace getNamespace() {
		return namespace;
	}
	
	public Vtable getAssociatedVtable() {
		return vtable;
	}

	public boolean isInternal() {
		return isInternal;

	}

	public boolean isPrimary() {
		return !isInternal;
	}

	public void setContainingClass(RecoveredClass recoveredClass) {
		containingClass = recoveredClass;
	}

	public RecoveredClass getContainingClass() {
		return containingClass;
	}

	public void setOffset(Long offset) {
		classOffset = offset;
	}

	public Long getClassOffset() {
		return classOffset;
	}

	public void setAssociatedClass(RecoveredClass recoveredClass) {
		associatedClass = recoveredClass;
	}

	public RecoveredClass getAssociatedClass() {
		return associatedClass;
	}
	
	public void addVfunction(Address address) {
		vfunctions.add(address);
	}
	
	public int getNumVfunctions() {
		return vfunctions.size();
	}
	//TODO: return num non-null vfunctions
}
