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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SpecialVtable extends Vtable {
	
	Address refFromTypeinfos;
	
	public SpecialVtable(Program program, Address vtableAddress, GccTypeinfoRef typeinfoRef, boolean inExternalMemory, Namespace classNamespace, TaskMonitor monitor) throws  CancelledException {
		
		super(program, vtableAddress, typeinfoRef, true, inExternalMemory, monitor);
		this.classNamespace = classNamespace;
	}
	
	@Override
	protected void setup() throws CancelledException {
		
		if(inExternalMemory) {
			
			refFromTypeinfos = vtableAddress;
			isConstruction = false;
			isPrimary = true;
			typeinfoAddress = vtableAddress;
			length = defaultPointerSize;
			hasVfunctions = false;
			return;
		}
		
		typeinfoRefAddress = vtableAddress.add(defaultPointerSize);					
				
		
		setTypeinfoAddress();
		
		if(!isValid) {
			return;
		}
		
		setTopOffsetValue();
		
		if(!isValid) {
			return;
		}
		
		isPrimary = true;
	
		
		setHasVfunctions();
		
		if(!isValid) {
			return;
		}
		
		isConstruction = false;
		
		classNamespace = typeinfoNamespace;
		
		
		setLength();
		
	}
	
	public Address getRefFromTypeinfos() {
		return refFromTypeinfos;
	}
	
}
