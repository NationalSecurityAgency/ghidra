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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

/**
 * Command for setting a function's return type.
 */
public class SetReturnDataTypeCmd implements Command {
	private Address entry;
	private DataType dataType;
	private String status;
	private SourceType source;

	/**
	 * Constructs a new command for setting a function's return type.
	 * @param entry the entry point of the function having its return type set.
	 * @param dataType the datatype to set on the function.
	 * @param source TODO
	 */
	public SetReturnDataTypeCmd(Address entry, DataType dataType, SourceType source) {
		this.entry = entry;
		this.dataType = dataType;
		this.source = source;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Set Return Data Type";
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		Function function = program.getListing().getFunctionAt(entry);
		try {
			function.setReturnType(dataType, source);
			if (source == SourceType.DEFAULT) {
				function.setSignatureSource(SourceType.DEFAULT);
			}
		}
		catch (InvalidInputException e) {
			status = e.getMessage();
			return false;
		}
		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return status;
	}

}
