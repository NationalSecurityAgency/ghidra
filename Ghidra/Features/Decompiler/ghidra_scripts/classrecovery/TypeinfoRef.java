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

import ghidra.program.model.address.Address;

public class TypeinfoRef {
	
	private Address address;
	private Typeinfo typeinfo;
	private Boolean inVtable = null;
	
	TypeinfoRef(Address address, Typeinfo typeinfo){
		this.address = address;
		this.typeinfo = typeinfo;
	}
	
	TypeinfoRef(Address address, Typeinfo typeinfo, Boolean inVtable){
		this.address = address;
		this.typeinfo = typeinfo;
		this.inVtable = inVtable;
	}
	
	public Address getAddress() {
		return address;
	}
	
	public Typeinfo getReferencedTypeinfo() {
		return typeinfo;
	}
	
	public void setIsInVtable(Boolean setting) {
		inVtable = setting;
	}
	
	public Boolean isInVtable() {
		return inVtable;
	}
}
