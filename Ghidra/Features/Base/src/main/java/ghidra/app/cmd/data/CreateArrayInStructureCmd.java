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
import ghidra.util.Msg;

/**
 * Command to create an array inside of a structure. All conflicting components
 * within the targeted structure will be replaced with the new array component. 
 * 
 */
public class CreateArrayInStructureCmd implements Command {
	private String msg;
	private Address addr;
	private int numElements;
	private DataType dataType;
	private int[] compPath;
	
	// NOTE: This command does not currently handle Dynamic types whose length may
	// be specified since no elementLength parameter exists.

	/**
	 * Constructs a new command for creating arrays inside of structures.
	 * The specified component will be replaced as will subsequent components within 
	 * the structure required to make room for the new array component.
	 * NOTE: This is intended for replacing existing components and not for
	 * simply inserting an array component. 
	 * @param addr The address of the structure that will contain the new array.
	 * @param numElements the number of elements in the array to be created.  A 0 element count is permitted.
	 * @param dt the dataType of the elements in the array to be created.
	 * @param compPath the target component path within the structure of an existing component where 
	 * the array should be created. The component path is an array of integers where each integer
	 * is a component index of the component above it.  
	 */	
	public CreateArrayInStructureCmd(Address addr, int numElements, DataType dt,
									  int[] compPath) {
		this.addr = addr;
		this.numElements = numElements;
		this.dataType = dt;
		this.compPath = compPath;
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program)obj;
		Listing listing = program.getListing();

		Data data = listing.getDataContaining(addr);
		Data compData = data.getComponent(compPath);
		if (compData == null) {
			msg = "Invalid target component path specified";
			return false;
		}

        int index = compData.getComponentIndex();
        int offset = compData.getParentOffset();
        DataType parentDataType = compData.getParent().getBaseDataType();

        if (!(parentDataType instanceof Structure)) {
            msg = "Data not in a structure";
            return false;
        }
        Structure struct = (Structure)parentDataType;

		DataType baseDt = dataType;
		if (dataType instanceof TypeDef) {
			baseDt = ((TypeDef) dataType).getBaseDataType();
		}
		if (baseDt instanceof Dynamic) {
			msg = "Dynamic data-type may not be specified: " + dataType.getName();
			return false;
		}

		try {
        	ArrayDataType adt = new ArrayDataType(dataType, numElements, dataType.getLength());
			int length = adt.isZeroLength() ? 0 : adt.getLength();
			if (!struct.isPackingEnabled() && (offset + length) > struct.getLength()) {
				msg = "Array too big for structure";
				return false;
			}
			clearStruct(struct, compData.getParentOffset(), length);
			if (struct.isPackingEnabled()) {
				struct.insert(index, adt, -1);
			}
			else {
				struct.replace(index, adt, -1);
			}
		}
		catch (RuntimeException e) {
			msg = "Unexpected error: " + e.toString();
			Msg.error(this, msg, e);
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
	@Override
	public String getStatusMsg() {
		return msg;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Create Array";
	}

}
