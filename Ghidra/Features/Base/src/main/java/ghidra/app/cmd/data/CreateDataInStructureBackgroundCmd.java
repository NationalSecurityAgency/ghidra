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

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 *
 * Background command to create data across a selection inside of a structure.
 *  
 */
public class CreateDataInStructureBackgroundCmd extends BackgroundCommand {

	private Address addr;
	private int length;
	private int[] startPath;
	private DataType newDataType;
	private boolean stackPointers;

	/**
	 * Constructs a command for applying dataTypes within an existing structure
	 * across a range of components.
	 * Simple pointer conversion will NOT be performed.
	 * @param addr The address of the existing structure.
	 * @param startPath the componentPath where to begin applying the datatype.
	 * @param length the number of bytes to apply the data type to.
	 * @param dt the datatype to be applied to the range of components.
	 */
	public CreateDataInStructureBackgroundCmd(Address addr, int[] startPath, int length,
			DataType dt) {
		this(addr, startPath, length, dt, false);
	}

	/**
	 * This is the same as {@link #CreateDataInStructureBackgroundCmd(Address, int[], int, DataType )} except that
	 * it allows the caller to control whether or not a pointer data type is created when a 
	 * non-pointer data type is applied at a location that previously contained a pointer data
	 * type.
	 *  
	 * @param addr The address of the existing structure.
	 * @param startPath the componentPath where to begin applying the datatype.
	 * @param length the number of bytes to apply the data type to.
	 * @param dt the datatype to be applied to the range of components.
	 * @param stackPointers True will convert the given data type to a pointer if it is not one
	 * and the previous type was a pointer; false will not make this conversion
	 */
	public CreateDataInStructureBackgroundCmd(Address addr, int[] startPath, int length,
			DataType dt, boolean stackPointers) {
		super("Create " + dt.getDisplayName() + " component(s)", false, true, true);
		this.addr = addr;
		this.startPath = startPath;
		this.length = length;
		this.newDataType = dt;
		this.stackPointers = stackPointers;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		Program program = (Program) obj;
		Data data = program.getListing().getDefinedDataContaining(addr);
		Data startData = data.getComponent(startPath);
		if (startData == null) {
			setStatusMsg("Component data not found");
			return false;
		}

		Data parent = startData.getParent();
		DataType parentDataType = parent.getBaseDataType();

		if (!(parentDataType instanceof Structure)) {
			setStatusMsg("Range based operation only supported within Structures");
			return false;
		}

		DataType existingDT = startData.getDataType();
		int startIndex = startData.getComponentIndex();
		Data lastComp = parent.getComponentAt(
			(int) (startData.getMinAddress().subtract(parent.getMinAddress()) + length - 1));
		int endIndex = lastComp.getComponentIndex();

		Structure struct = (Structure) parentDataType;

		// TODO: Is looking at the first component data-type (existingDT) the right thing to do for a selection ??

		if (newDataType instanceof FactoryDataType) {
			setStatusMsg("Factory data-type not allowed in structure: " + newDataType.getName());
			return false;
		}

		newDataType = newDataType.clone(program.getDataTypeManager());
		newDataType =
			DataUtilities.reconcileAppliedDataType(existingDT, newDataType, stackPointers);

		if (newDataType instanceof Dynamic && !((Dynamic) newDataType).canSpecifyLength()) {
			setStatusMsg(
				"Non-sizable Dynamic data-type not allowed in structure: " + newDataType.getName());
			return false;
		}

		for (int i = endIndex; i >= startIndex; i--) {
			struct.clearComponent(i);
		}

		if (newDataType != DataType.DEFAULT) {
			int index = startIndex;
			int numCreated = 0;
			while (length > 0) {
				try {
//			        MemBuffer memBuf = new ProgramStructureProviderContext(program,addr, 
//    	    	    					struct, struct.getComponent(index).getOffset());
					DataTypeInstance dti =
						DataTypeInstance.getDataTypeInstance(newDataType, length);
					if (dti == null || dti.getLength() > length) {
						break;
					}
					DataTypeComponent dtc =
						struct.replace(index, dti.getDataType(), dti.getLength());
					length -= dtc.getLength();
					numCreated++;
					index++;
				}

				catch (Exception e) {
					setStatusMsg(e.getMessage());
					return false;
				}
			}
			if (numCreated == 0) {
				setStatusMsg("Not enough space");
				return false;
			}
		}
		return true;
	}

}
