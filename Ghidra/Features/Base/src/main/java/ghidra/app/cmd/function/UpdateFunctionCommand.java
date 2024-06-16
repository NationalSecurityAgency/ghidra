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

import java.util.List;

import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * A command to update {@link Function} signature in its entirety including optional
 * custom storage.
 * 
 * If the function does not rely on custom storage the use of {@link ApplyFunctionSignatureCmd}
 * may be more appropriate.
 */
public class UpdateFunctionCommand implements Command<Program> {

	private final Function function;
	private final FunctionUpdateType updateType;
	private final String callingConvention;
	private final Variable returnVar;
	private final List<? extends Variable> params;
	private final SourceType source;
	private final boolean force;

	private String statusMessage;

	/**
	 * Construct command to update a {@link Function} signature including optional custom storage.
	 * {@link VariableStorage#UNASSIGNED_STORAGE} should be specified when not using custom storage
	 * or storage is unknown.
	 * 
	 * @param function function to be modified
	 * @param updateType indicates how function should be updated including the use of custom or
	 * non-custom storage.
	 * @param callingConvention a valid calling convention name or null if no change is required.
	 * Calling conventions are limited to {@value Function#DEFAULT_CALLING_CONVENTION_STRING},
	 * {@value Function#UNKNOWN_CALLING_CONVENTION_STRING} or those defined by the associated 
	 * compiler specification.
	 * @param returnVar function return type and storage.
	 * @param params function parameter list (specifics depend on specified 
	 * {@link FunctionUpdateType updateType}).
	 * @param source  the source of these parameters which will be applied to the parameter 
	 * symbols and overall function signature source. If parameter names are null, or a default 
	 * name, a {@link SourceType#DEFAULT} will be applied to the corresponding parameter symbol.
	 * @param force if true any conflicting local parameters will be removed
	 */
	public UpdateFunctionCommand(Function function, FunctionUpdateType updateType,
			String callingConvention, Variable returnVar, List<? extends Variable> params,
			SourceType source, boolean force) {
		this.function = function;
		this.updateType = updateType;
		this.callingConvention = callingConvention;
		this.returnVar = returnVar;
		this.params = params;
		this.source = source;
		this.force = force;
	}

	@Override
	public boolean applyTo(Program obj) {
		try {
			function.updateFunction(callingConvention, returnVar, params, updateType, force,
				source);
			return true;
		}
		catch (InvalidInputException | DuplicateNameException e) {
			statusMessage = e.getMessage();
			return false;
		}
	}

	@Override
	public String getStatusMsg() {
		return statusMessage;
	}

	@Override
	public String getName() {
		return "Update Function";
	}

}
