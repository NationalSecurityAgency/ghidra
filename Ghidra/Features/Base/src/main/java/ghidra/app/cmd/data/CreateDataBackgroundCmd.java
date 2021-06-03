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
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

/**
 * This command will create a data of type dataType throughout an addressSet. 
 * If there are any existing
 * instructions in the area to be made into data, the command will fail.  Any data
 * in the area will be replaced with the new dataType, except when the existing data
 * or the given dataType is a pointer.  If the existing dataType is a pointer, then
 * it will be changed into a pointer to the given dataType.  If the given dataType
 * is a pointer and the existing data is &gt;= to the size of a pointer, it will become
 * a pointer to the existing type.  If the existing dataType is less than the size
 * of a pointer, then a pointer to dataType will only be created if there are
 * enough undefined bytes following to make a pointer.
 */
public class CreateDataBackgroundCmd extends BackgroundCommand {
	private static final int EVENT_LIMIT = 1000;

	private AddressSetView addrSet;
	private DataType newDataType;
	private int bytesApplied = 0;
	private int numDataCreated = 0;
	private boolean stackPointers;

	/**
	 * Constructs a command for applying a dataType to a set of addresses.
	 * Simple pointer conversion will NOT be performed.
	 * @param addrSet The address set to fill with the given dataType.
	 * @param dataType the dataType to be applied to the address set.
	 */
	public CreateDataBackgroundCmd(AddressSetView addrSet, DataType dataType) {
		this(addrSet, dataType, false);
	}

	/**
	 * This is the same as {@link #CreateDataBackgroundCmd(AddressSetView, DataType)} except that
	 * it allows the caller to control whether or not a pointer data type is created when a 
	 * non-pointer data type is applied at a location that previously contained a pointer data
	 * type.
	 *  
	 * @param addrSet The address set to fill with the given dataType.
	 * @param dataType the dataType to be applied to the address set.
	 * @param stackPointers if true simple pointer conversion is enabled 
	 * (see {@link DataUtilities#reconcileAppliedDataType(DataType, DataType, boolean)}).
	 */
	public CreateDataBackgroundCmd(AddressSetView addrSet, DataType dataType,
			boolean stackPointers) {
		super("Create " + dataType.getDisplayName() + "(s)", true, true, true);
		this.newDataType = dataType;
		this.addrSet = addrSet;
		this.stackPointers = stackPointers;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		return doApplyTo(obj, monitor);
	}

	public boolean doApplyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;
		Listing listing = program.getListing();
		InstructionIterator iter = listing.getInstructions(addrSet, true);
		if (iter.hasNext()) {
			setStatusMsg("Can't create data because the current selection contains instructions");
			return false;
		}

		Address addr = addrSet.getMinAddress();
		Data data = listing.getDataAt(addr);
		if (data == null) {
			setStatusMsg("Can not create Data at address " + addr);
			return false;
		}

		DataType existingDT = data.getDataType();

		newDataType = newDataType.clone(program.getDataTypeManager());
		newDataType =
			DataUtilities.reconcileAppliedDataType(existingDT, newDataType, stackPointers);

		monitor.initialize(addrSet.getNumAddresses());
		AddressRangeIterator it = addrSet.getAddressRanges();
		while (it.hasNext() && !monitor.isCancelled()) {
			AddressRange range = it.next();
			try {
				createData(range.getMinAddress(), range.getMaxAddress(), newDataType, program,
					monitor);
			}
			catch (Exception e) {
				setStatusMsg(e.getMessage());
				if (numDataCreated == 0) {
					return false;
				}
			}

		}
		if (numDataCreated == 0) {
			setStatusMsg("Not Enough space to create Data");
			return false;
		}

		return true;
	}

	private void createData(Address start, Address end, DataType dataType, Program p,
			TaskMonitor monitor)
			throws AddressOverflowException, CodeUnitInsertionException, DataTypeConflictException {

		Listing listing = p.getListing();
		listing.clearCodeUnits(start, end, false);
		int length = (int) end.subtract(start) + 1;
		while (start.compareTo(end) <= 0) {
			if (monitor.isCancelled()) {
				return;
			}

			Data d = listing.createData(start, dataType, length);
			int dataLen = d.getLength();
			start = start.addNoWrap(dataLen);
			length -= dataLen;
			bytesApplied += dataLen;

			monitor.setProgress(bytesApplied);
			if (++numDataCreated % 10000 == 0) {
				monitor.setMessage("Created " + numDataCreated);

				// Allow the Swing thread a chance to paint components that may require
				// a DB lock.
				Swing.allowSwingToProcessEvents();
			}
		}
	}
}
