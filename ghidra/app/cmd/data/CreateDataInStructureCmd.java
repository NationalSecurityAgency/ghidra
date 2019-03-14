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
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

/**
 * Command to Create data inside of a structure.
 */
public class CreateDataInStructureCmd implements Command {

	private Address addr;
	private int[] componentPath;
	private DataType newDataType;
	private String msg;
	private boolean stackPointers;

	/**
	 * Constructs a new command for creating data inside a structure.
	 * Simple pointer conversion will NOT be performed.
	 * @param addr the address of the structure in which to apply the given datatype.
	 * @param componentPath the component path of the component where the datatype
	 * will be applied.
	 * @param dt the datatype to apply in the structure.
	 */
	public CreateDataInStructureCmd(Address addr, int[] componentPath, DataType dt) {
		this(addr, componentPath, dt, false);
	}

	/**
	 * This is the same as {@link #CreateDataInStructureCmd(Address, int[], DataType)} except that
	 * it allows the caller to control whether or not a pointer data type is created when a 
	 * non-pointer data type is applied at a location that previously contained a pointer data
	 * type.
	 *  
	 * @param addr the address of the structure in which to apply the given datatype.
	 * @param componentPath the component path of the component where the datatype
	 * will be applied.
	 * @param dt the datatype to apply in the structure.
	 * @param stackPointers if true simple pointer conversion is enabled 
	 * (see {@link DataUtilities#reconcileAppliedDataType(DataType, DataType, boolean)}).
	 */
	public CreateDataInStructureCmd(Address addr, int[] componentPath, DataType dt,
			boolean stackPointers) {
		this.addr = addr;
		this.componentPath = componentPath;
		this.newDataType = dt;
		this.stackPointers = stackPointers;
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		Data data = program.getListing().getDefinedDataContaining(addr);
		Data dataComp = data.getComponent(componentPath);
		if (dataComp == null) {
			msg = "Component data not found";
			return false;
		}

		DataType parentDataType = dataComp.getParent().getBaseDataType();

		if (!(parentDataType instanceof Composite)) {
			msg = "Invalid command usage";
			return false;
		}

		if (newDataType instanceof FactoryDataType) {
			msg = "Factory data-type not allowed in structure or union: " + newDataType.getName();
			return false;
		}

		DataType existingDT = dataComp.getDataType();
		int index = dataComp.getComponentIndex();

		newDataType =
			DataUtilities.reconcileAppliedDataType(existingDT, newDataType, stackPointers);

		if (newDataType instanceof Dynamic) {
			msg = "Dynamically sized data-type not allowed: " + newDataType.getName();
			return false;
		}

		// Ensure that dynamically sized types adjust to the data type manager
		newDataType = program.getDataTypeManager().resolve(newDataType, null);

		try {
			if (parentDataType instanceof Structure) {
				Structure struct = (Structure) parentDataType;
				if (newDataType == DataType.DEFAULT) {
					struct.clearComponent(index);
				}
				else {
//			        MemBuffer memBuf = new ProgramStructureProviderContext(program,addr, 
//	    	        					struct, dataComp.getParentOffset());
					DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(newDataType, -1);
					struct.replace(index, dti.getDataType(), dti.getLength());
				}
			}
			else if (parentDataType instanceof Union) {
				Union union = (Union) parentDataType;
				DataTypeComponent comp = union.getComponent(index);
				String comment = comp.getComment();
				String fieldName = comp.getFieldName();
				union.insert(index, newDataType);
				union.delete(index + 1);
				comp = union.getComponent(index);
				comp.setComment(comment);
				comp.setFieldName(fieldName);
			}

		}
		catch (Exception e) {
			msg = e.getMessage();
			return false;
		}
		return true;
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
		return "Create " + newDataType.getDisplayName() + " component";
	}

}
