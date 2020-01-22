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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Program;

/**
 * This command will create a data of type dataType at the given address.  This
 * command will only work for fixed length dataTypes.  If there are any existing
 * instructions in the area to be made into data, the command will fail.  Existing data
 * in the area may be replaced with the new dataType (with optional pointer conversion).  
 * If the existing dataType is a pointer, then
 * the existing data will be changed into a pointer to the given dataType.  If the given dataType
 * is a default-pointer, it will become a pointer to the existing type.  
 * 
 * @see DataUtilities#createData(Program, Address, DataType, int, boolean, DataUtilities.ClearDataMode)
 */
public class CreateDataCmd implements Command {

	private Address addr;
	private DataType newDataType;
	private String cmdName;
	private String msg;
	private DataUtilities.ClearDataMode clearMode;
	private boolean stackPointers;

	/**
	 * Constructs a command for creating data at an address.
	 * Simple pointer conversion will NOT be performed.
	 * Existing Undefined data will always be cleared even when force is false.
	 * @param addr the address at which to apply the datatype.  Offcut data
	 * address allowed, provided force==true.
	 * @param force if true any existing conflicting data will be cleared
	 * @param dataType the datatype to be applied at the given address.
	 */
	public CreateDataCmd(Address addr, boolean force, DataType dataType) {
		this(addr, dataType, false, force ? DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
				: DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
	}

	/**
	 * This is the same as {@link #CreateDataCmd(Address, boolean, DataType)} except that
	 * it allows the caller to control whether or not pointer conversion should be handled.
	 * 
	 * @param addr the address at which to apply the datatype.  Offcut data
	 * address allowed, provided force==true.
	 * @param force if true any existing conflicting data will be cleared
	 * @param stackPointers if true simple pointer conversion is enabled 
	 * (see {@link DataUtilities#reconcileAppliedDataType(DataType, DataType, boolean)}).
	 * @param dataType the datatype to be applied at the given address.
	 */
	public CreateDataCmd(Address addr, boolean force, boolean stackPointers, DataType dataType) {
		this(addr, dataType, stackPointers,
			force ? DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
					: DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
	}

	/**
	 * Constructs a command for creating data at an address.
	 * Simple pointer conversion will NOT be performed and existing 
	 * defined data will not be cleared, however existing Undefined data will
	 * be cleared.
	 * @param addr the address at which to apply the datatype.
	 * @param dataType the datatype to be applied at the given address.
	 */
	public CreateDataCmd(Address addr, DataType dataType) {
		this(addr, dataType, false, false);
	}

	/**
	 * This is the same as {@link #CreateDataCmd(Address, DataType)} except that
	 * it allows the caller to control whether or not pointer conversion should be handled.
	 * Existing Undefined data will always be cleared.
	 * @param addr the address at which to apply the datatype.
	 * @param dataType the datatype to be applied at the given address.
	 * @param isCycle true indicates this is from a cycle group action.
	 * @param stackPointers if true simple pointer conversion is enabled 
	 * (see {@link DataUtilities#reconcileAppliedDataType(DataType, DataType, boolean)}).
	 */
	public CreateDataCmd(Address addr, DataType dataType, boolean isCycle, boolean stackPointers) {
		this(addr, dataType, stackPointers, isCycle ? DataUtilities.ClearDataMode.CLEAR_SINGLE_DATA
				: DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
	}

	/**
	 * This constructor provides the most flexibility when creating data, allowing optional pointer conversion and
	 * various clearing options for conflicting data.  
	 * @param addr the address at which to apply the datatype.
	 * @param dataType the datatype to be applied at the given address.
	 * @param stackPointers if true simple pointer conversion is enabled 
	 * (see {@link DataUtilities#reconcileAppliedDataType(DataType, DataType, boolean)}).
	 * @param clearMode indicates how conflicting data should be cleared
	 */
	public CreateDataCmd(Address addr, DataType dataType, boolean stackPointers,
			DataUtilities.ClearDataMode clearMode) {
		this.newDataType = dataType;
		this.addr = addr;
		this.stackPointers = stackPointers;
		this.clearMode = clearMode;
		cmdName = "Create " + dataType.getDisplayName();
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		try {
			DataUtilities.createData((Program) obj, addr, newDataType, -1, stackPointers,
				clearMode);
			return true;
		}
		catch (Exception e) {
			msg = e.getMessage();
			return false;
		}
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}

	@Override
	public String getName() {
		return cmdName;
	}
}
