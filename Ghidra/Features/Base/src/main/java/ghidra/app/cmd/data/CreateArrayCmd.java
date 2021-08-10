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
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;

/**
 * Command to create an array.  All conflicting data will be cleared.
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
	 * A 0 element count is permitted but a minimum length will apply for all array instances.
	 * @param dt the dataType of the elements in the array to be created.
	 * @param elementLength the size of an element in the array.  Only used for Dynamic
	 * datatype <code>dt</code> when {@link Dynamic#canSpecifyLength()} returns true.
	 */	
	public CreateArrayCmd(Address addr, int numElements, DataType dt, int elementLength) {
		this.addr = addr;
		this.numElements = numElements;
		this.dataType = dt;
		this.elementLength = elementLength;
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program)obj;
		Listing listing = program.getListing();
		try {
			ArrayDataType adt = new ArrayDataType(dataType, numElements, elementLength,
				program.getDataTypeManager());
			int length = adt.getLength();

			Address endAddr = addr.addNoWrap(length - 1);
			AddressSet set = new AddressSet(addr, endAddr);
			InstructionIterator iter = listing.getInstructions(set, true);
			if (iter.hasNext()) {
				msg = "Can't create data because the current selection contains instructions";
				return false;
			}
			listing.clearCodeUnits(addr, endAddr, false);
			listing.createData(addr, adt, adt.getLength());
		} catch (AddressOverflowException e1) {
			msg = "Can't create data because length exceeds address space";
			return false;
		}
		catch (IllegalArgumentException | CodeUnitInsertionException e) {
			msg = e.getMessage();
			return false;
		}
		catch (RuntimeException e) {
			msg = "Unexpected error: " + e.toString();
			Msg.error(this, msg, e);
			return false;
		}
		return true; 
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}

	@Override
	public String getName() {
		return "Create Array";
	}

}
