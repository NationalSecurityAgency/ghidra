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
package ghidra.app.cmd.data;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;

/**
 * Command to create an array.
 * 
 */
public class CreateArrayCmd implements Command {
	private String msg;
	private Address addr;
	private int numElements;
	private int elementLength;
	private DataType dataType;

	/**
	 * Constructs a new command for creating arrays.
	 * @param addr The address at which to create an array.
	 * @param numElements the number of elements in the array to be created.
	 * @param dt the dataType of the elements in the array to be created.
	 * @param elementLength the size of an element in the array.
	 */	
	public CreateArrayCmd(Address addr, int numElements, DataType dt, int elementLength) {
		this.addr = addr;
		this.numElements = numElements;
		this.dataType = dt;
		this.elementLength = elementLength;
	}
	
	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */	
	public boolean applyTo(DomainObject obj) {
		Program program = (Program)obj;
		Listing listing = program.getListing();
		
        if (dataType instanceof FactoryDataType) {
			msg = "Array not allowed on a Factory data-type: " + dataType.getName();
			return false;
		}
		if (dataType instanceof Dynamic && !((Dynamic)dataType).canSpecifyLength()) {
			msg = "Array not allowed on a non-sizable Dynamic data-type: " + dataType.getName();
			return false;
		}
		if (elementLength <=0) {
			msg = "DataType must have fixed size > 0, not "+dataType.getLength();
			return false;
		}
		if (numElements <= 0) {
			msg = "Number of elements must be positive, not "+numElements;
			return false;
		}
		
		int length = numElements*elementLength;
		Address endAddr;
		try {
			endAddr = addr.addNoWrap(length - 1);
		} catch (AddressOverflowException e1) {
			msg = "Can't create data because length exceeds address space";
			return false;
		}
		AddressSet set = new AddressSet(addr, endAddr);
        InstructionIterator iter = listing.getInstructions(set, true);
        if (iter.hasNext()) {
        	msg = "Can't create data because the current selection contains instructions";
         	return false;
        }
        
        listing.clearCodeUnits(addr, endAddr, false);
        ArrayDataType adt = new ArrayDataType(dataType, numElements, elementLength);
		try {
			listing.createData(addr, adt, adt.getLength());
		} catch(CodeUnitInsertionException e) {
			msg = e.getMessage();
			return false;
		}
		return true; 
	}


	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	public String getStatusMsg() {
		return msg;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	public String getName() {
		return "Create Array";
	}

}
