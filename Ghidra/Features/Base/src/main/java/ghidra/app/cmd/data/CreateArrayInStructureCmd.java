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
package ghidra.app.cmd.data;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

/**
 * Command to create an array inside of a structure.
 * 
 */
public class CreateArrayInStructureCmd implements Command {
	private String msg;
	private Address addr;
	private int numElements;
	private DataType dataType;
	private int[] compPath;
	
	/**
	 * Constructs a new command for creating arrays inside of structures.
	 * @param addr The address of the structure that will contain the new array.
	 * @param numElements the number of elements in the array to be created.
	 * @param dt the dataType of the elements in the array to be created.
	 * @param compPath the component path within the structure at which to create
	 * the array. The component path is an array of integers where each integer
	 * is a component index of the component above it.
	 */	
	public CreateArrayInStructureCmd(Address addr, int numElements, DataType dt,
									  int[] compPath) {
		this.addr = addr;
		this.numElements = numElements;
		this.dataType = dt;
		this.compPath = compPath;
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
		if (numElements <= 0) {
			msg = "Number of elements must be positive, not "+numElements;
			return false;
		}

		Data data = listing.getDataContaining(addr);
		Data compData = data.getComponent(compPath);
		
		int elementLength;
		if (dataType instanceof Dynamic) {
			elementLength = compData.getLength();
		}
		else {
			elementLength = dataType.getLength();
		}
		if (elementLength <=0) {
			msg = "DataType must have fixed size > 0, not "+elementLength;
			return false;
		}
		int length = numElements*elementLength;

        int index = compData.getComponentIndex();
        int offset = compData.getParentOffset();
        DataType parentDataType = compData.getParent().getBaseDataType();

        if (!(parentDataType instanceof Structure)) {
            msg = "Data not in a structure";
            return false;
        }
        Structure struct = (Structure)parentDataType;
       	if (offset+length > struct.getLength()) {
       		msg = "Array too big for structure";
       		return false;
       	}

		try {
        	ArrayDataType adt = new ArrayDataType(dataType, numElements, dataType.getLength());
			clearStruct(struct, compData.getParentOffset(), length);
			if (struct.isPackingEnabled()) {
				struct.insert(index, adt, adt.getLength());
			}
			else {
				struct.replace(index, adt, adt.getLength());
			}
		}
		catch(Exception e) {
			msg = e.getMessage();
			return false;
		}	
		return true;
	}

	private void clearStruct(Structure struct, int offset, int length) {
		DataTypeComponent[] comps = struct.getDefinedComponents();
		int endOffset = offset+length;
		for(int i=comps.length-1;i>=0;i--) {
			if (comps[i].getOffset() >= offset && comps[i].getOffset() < endOffset) {
				struct.clearComponent(comps[i].getOrdinal());
			}
		}
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
