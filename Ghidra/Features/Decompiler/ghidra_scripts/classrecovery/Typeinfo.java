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
import ghidra.program.model.symbol.Namespace;

public class Typeinfo {
	
	private Address address;
	private Namespace classNamespace;
	private Boolean hasDefinedStructure = false;
	
	Typeinfo(Address address, Namespace classNamespace){
		this.address = address;
		this.classNamespace = classNamespace;
	}
	
	public Address getAddress() {
		return address;
	}
	
	public Namespace getNamespace() {
		return classNamespace;
	}
	
	/**
	 * method to define if has defined structure or not
	 * @param setting true - has defined structure, false - not yet defined, null - not enough memory to defined a structure
	 */
	private void setHasDefinedStructure(Boolean setting) {
		hasDefinedStructure = setting;
	}
	
	public Boolean hasDefinedStructure() {
		return hasDefinedStructure;
	}
	
}
