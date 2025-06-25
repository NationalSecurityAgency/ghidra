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

import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Allows for the adding of a parameter to a given function.
 * 
 * Note: If no ordinal is provided to this class at construction time, then
 * the ordinal of hte given parameter will be used.
 * 
 * @see AddRegisterParameterCommand
 * @see AddStackParameterCommand
 * @see AddMemoryParameterCommand
 * 
 * @deprecated function signatures should be modified in their entirety using 
 * either {@link UpdateFunctionCommand} or {@link ApplyFunctionSignatureCmd}. 
 */
@Deprecated(forRemoval = true, since = "11.1")
public class AddParameterCommand implements Command<Program> {

	protected final Function function;
	protected final int ordinal;
	protected final SourceType source;

	private final Parameter parameter;

	protected String statusMessage;

	public AddParameterCommand(Function function, Parameter parameter, int ordinal,
			SourceType source) {
		this.function = function;
		this.parameter = parameter;
		this.ordinal = ordinal;
		this.source = source;
	}

	// allows subclasses to use this class without having to already have
	// a parameter created
	protected AddParameterCommand(Function function, int ordinal, SourceType source) {
		this(function, null, ordinal, source);
	}

	/**
	 * Get parameter to be added
	 * @param program target program
	 * @return parameter to be added
	 * @throws InvalidInputException if unable to generate parameter due to invalid data
	 */
	protected Parameter getParameter(Program program) throws InvalidInputException {
		return parameter;
	}

	@Override
	public final boolean applyTo(Program program) {
		if (program != function.getProgram()) {
			throw new AssertionError("Program instance mismatch");
		}
		String name = null;
		try {
			Parameter param = getParameter(program);
			name = param.getName();
			if (function.insertParameter(ordinal, param, source) == null) {
				statusMessage = "Create parameter failed";
				return false;
			}
		}
		catch (DuplicateNameException e) {
			statusMessage = "Parameter named " + name + " already exists";
			return false;
		}
		catch (Exception exc) {
			Throwable cause = exc.getCause();
			if (cause != null) {
				statusMessage = cause.getMessage();
				if (statusMessage == null) {
					statusMessage = cause.getClass().getName();
				}
			}
			else {
				statusMessage = exc.getMessage();
				if (statusMessage == null) {
					statusMessage = exc.getClass().getName();
				}
			}
			return false;
		}

		return true;
	}

	@Override
	public String getStatusMsg() {
		return statusMessage;
	}

	@Override
	public String getName() {
		return "Add Parameter Command";
	}
}
