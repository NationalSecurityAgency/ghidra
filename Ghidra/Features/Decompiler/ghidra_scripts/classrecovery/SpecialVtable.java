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

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
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

		// check for vtable has memory but all zeros or has possible invalid values which in both
		// cases would make the pointer to special typeinfo invalid
		if (hasSpecialCopyUnhandledRelocation(vtableAddress)) {
			isConstruction = false;
			isPrimary = true;
			typeinfoAddress = null;
			length = 3 * defaultPointerSize; //actually prob 11*defPtr but are all zeros in this case
			hasVfunctions = true; // they are null though so will count as num=0, need this to be true so check for refs to vfunction top will work
			numVfunctions = 0;
			vfunctionTop = vtableAddress.add(2 * defaultPointerSize);
			return;
		}
				
		
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
		
		if (classNamespace == null) {
			classNamespace = typeinfoNamespace;
		}
		
		
		setLength();
		
	}
	
	public Address getRefFromTypeinfos() {
		return refFromTypeinfos;
	}
	
	private boolean hasSpecialCopyUnhandledRelocation(Address address) {

		RelocationTable relocationTable = program.getRelocationTable();

		List<Relocation> relocations = relocationTable.getRelocations(address);

		for (Relocation relocation : relocations) {

			Status status = relocation.getStatus();
			if (status == Status.UNSUPPORTED) {

				String symbolName = relocation.getSymbolName();

				if (symbolName == null || !symbolName.contains("class_type_info")) {
					continue;
				}

				//if relocation symbol is the same as the symbol at the relcation address
				//then this situation is not an issue - it indicates a copy relocation at the
				//location of the special typeinfo vtable which is a use case that can be handled
				Symbol symbolAtAddress = program.getSymbolTable()
						.getSymbol(symbolName, address, program.getGlobalNamespace());
				if (symbolAtAddress != null) {
					return true;
				}
			}
		}
		return false;
	}

}
