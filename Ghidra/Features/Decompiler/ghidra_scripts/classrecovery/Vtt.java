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

public class Vtt {
	
	Address vttAddress;
	Namespace namespace;
	List<Address> pointers = new ArrayList<Address>();
	
	public Vtt(Address vttAddress, Namespace namespace){
		this.vttAddress = vttAddress;
		this.namespace = namespace;
	}
	
	public Address getAddress() {
		return vttAddress;
	}
	
	public Namespace getNamespace() {
		return namespace;
	}
	
	public void addPointerToList(Address pointer) {
		pointers.add(pointer);
	}
	
	public boolean containsPointer(Address pointer) {
		return(pointers.contains(pointer));
	}
	
	public int getNumPtrs() {
		return pointers.size();
	}
}
