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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

/**
 * A command to create a new function memory parameter.
 */
public class AddMemoryParameterCommand extends AddParameterCommand {

	private Address memAddr;
	private String name;
	private DataType dataType;

	public AddMemoryParameterCommand(Function function, Address memAddr, String name,
			DataType dataType, int ordinal, SourceType source) {
		super(function, ordinal, source);
		this.memAddr = memAddr;
		this.name = name;
		this.dataType = dataType;
		this.ordinal = ordinal;
	}

	@Override
	protected Parameter getParameter(Program program) throws InvalidInputException {
		return new ParameterImpl(name, dataType, memAddr, program);
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Create Memory Parameter";
	}
}
