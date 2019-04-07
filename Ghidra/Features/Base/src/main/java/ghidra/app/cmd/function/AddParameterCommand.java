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
 * 
 * @see ghidra.app.cmd.function.AddRegisterParameterCommand
 * @see ghidra.app.cmd.function.AddStackParameterCommand
 */
public class AddParameterCommand implements Command {

	protected Function function;
	protected Parameter parameter;
	protected String statusMessage;
	protected int ordinal;
	protected SourceType source;

	public AddParameterCommand(Function function, Parameter parameter, int ordinal,
			SourceType source) {
		this.function = function;
		this.parameter = parameter;
		this.ordinal = ordinal;
		this.source = source;
	}

//	// lets this be usable by code that already has a parameter
//	public AddParameterCommand(Function function, Parameter parameter) {
//		this(function, parameter, parameter.getOrdinal());
//	}

	// allows subclasses to use this class without having to already have
	// a parameter created
	protected AddParameterCommand(Function function, int ordinal, SourceType source) {
		this(function, null, ordinal, source);
	}

	protected Parameter getParameter(Program program) throws InvalidInputException {
		return parameter;
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		String name = null;
		try {
			Parameter parameter2add = getParameter((Program) obj);
			name = parameter2add.getName();
			if (function.insertParameter(ordinal, parameter2add, source) == null) {
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

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return statusMessage;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Add Parameter Command";
	}
}
