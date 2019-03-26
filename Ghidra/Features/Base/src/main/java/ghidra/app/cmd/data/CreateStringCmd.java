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
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;

/**
 * Command to create a String and optionally label it.
 *
 */
public class CreateStringCmd implements Command {
	private final Address addr;
	private final AbstractStringDataType stringDataType;
	private int length = -1;
	private ClearDataMode clearMode;
	private String msg;

	private static AbstractStringDataType getStringDataType(boolean unicode, int length) {
		return unicode ? new UnicodeDataType()
				: (length > 0) ? new StringDataType() : new TerminatedStringDataType();
	}

	public CreateStringCmd(Address addr, AbstractStringDataType stringDataType, int length,
			ClearDataMode clearMode) {
		this.addr = addr;
		this.stringDataType = stringDataType;
		this.length = length;
		this.clearMode = clearMode;
	}

	/**
	 * Constructs a new command for creating strings.
	 */
	public CreateStringCmd(Address addr, int length, boolean unicode, ClearDataMode clearMode) {
		this(addr, getStringDataType(unicode, length), length, clearMode);
	}

	/**
	 * Constructs a new command for creating strings.
	 */
	public CreateStringCmd(Address addr, int length, boolean unicode) {
		this(addr, getStringDataType(unicode, length), length, ClearDataMode.CLEAR_SINGLE_DATA);
	}

	/**
	 * Constructs a new command for creating strings.
	 */
	public CreateStringCmd(Address addr) {
		this(addr, -1, false);
	}

	/**
	 * Constructs a new command for creating strings.
	 */
	public CreateStringCmd(Address addr, int length) {
		this(addr, length, false);
	}

	/**
	 *
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;

		try {
			DataUtilities.createData(program, addr, stringDataType, length, false, clearMode);
		}
		catch (CodeUnitInsertionException e) {
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
		return "Create String";
	}

}
