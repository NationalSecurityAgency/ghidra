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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;

/**
 * Command to create a String and optionally label it.
 *
 */
public class CreateStringCmd implements Command<Program> {
	private final Address addr;
	private final AbstractStringDataType stringDataType;
	private int length = -1;
	private ClearDataMode clearMode;
	private String msg;

	private static AbstractStringDataType getStringDataType(boolean unicode, int length) {
		return unicode ? new UnicodeDataType()
				: (length > 0) ? new StringDataType() : new TerminatedStringDataType();
	}

	/**
	 * Construct command for creating string Data
	 * @param addr address where string should be created.
	 * @param stringDataType string datatype
	 * @param length maximum string length (treatment is specific to specified datatype).
	 * @param clearMode {@link ClearDataMode} which indicates how existing Data conflicts
	 * should be handled.
	 */
	public CreateStringCmd(Address addr, AbstractStringDataType stringDataType, int length,
			ClearDataMode clearMode) {
		this.addr = addr;
		this.stringDataType = stringDataType;
		this.length = length;
		this.clearMode = clearMode;
	}

	/**
	 * Construct command for creating fixed-length ASCII or Unicode string Data
	 * @param addr address where string should be created.
	 * @param length byte-length of string
	 * @param unicode if true Unicode string will be created, else ASCII
	 * @param clearMode {@link ClearDataMode} which indicates how existing Data conflicts
	 * should be handled.
	 */
	public CreateStringCmd(Address addr, int length, boolean unicode, ClearDataMode clearMode) {
		this(addr, getStringDataType(unicode, length), length, clearMode);
	}

	/**
	 * Construct command for creating fixed-length ASCII or Unicode string Data.
	 * Current Data at addr will be cleared if it already exists.
	 * @param addr address where string should be created.
	 * @param length byte-length of string
	 * @param unicode if true Unicode string will be created, else ASCII
	 */
	public CreateStringCmd(Address addr, int length, boolean unicode) {
		this(addr, getStringDataType(unicode, length), length, ClearDataMode.CLEAR_SINGLE_DATA);
	}

	/**
	 * Construct command for creating null-terminated ASCII string Data.
	 * Current Data at addr will be cleared if it already exists.
	 * @param addr address where string should be created.
	 */
	public CreateStringCmd(Address addr) {
		this(addr, -1, false);
	}

	/**
	 * Construct command for creating fixed-length ASCII string Data.
	 * Current Data at addr will be cleared if it already exists.
	 * @param addr address where string should be created.
	 * @param length byte-length of string
	 */
	public CreateStringCmd(Address addr, int length) {
		this(addr, length, false);
	}

	@Override
	public boolean applyTo(Program program) {
		try {
			DataUtilities.createData(program, addr, stringDataType, length, clearMode);
		}
		catch (CodeUnitInsertionException e) {
			msg = e.getMessage();
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
		return "Create String";
	}

}
