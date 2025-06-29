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
package ghidra.app.cmd.function;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

/**
 * A command to create a new function stack parameter.
 * 
 * @deprecated function signatures should be modified in their entirety using 
 * either {@link UpdateFunctionCommand} or {@link ApplyFunctionSignatureCmd}. 
 */
@Deprecated(forRemoval = true, since = "11.1")
public class AddStackParameterCommand extends AddParameterCommand {

	private final int stackOffset;
	private final String name;
	private final DataType dataType;

	public AddStackParameterCommand(Function function, int stackOffset, String name,
			DataType dataType, int ordinal, SourceType source) {
		super(function, ordinal, source);
		this.stackOffset = stackOffset;
		this.name = name;
		this.dataType = dataType;
	}

	@Override
	protected Parameter getParameter(Program program) throws InvalidInputException {
		return new ParameterImpl(name, dataType, stackOffset, program);
	}

	@Override
	public String getName() {
		return "Add Stack Parameter";
	}

}
