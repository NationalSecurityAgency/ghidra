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
package ghidra.program.model.listing;

import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

public class AutoParameterImpl extends ParameterImpl {

	private Function function;

	public AutoParameterImpl(DataType dataType, int ordinal, VariableStorage storage,
			Function function) throws InvalidInputException {
		super(getAutoName(storage.getAutoParameterType()), ordinal, dataType, storage, false,
			function.getProgram(), SourceType.ANALYSIS);
		if (storage.isForcedIndirect() || !storage.isAutoStorage()) {
			throw new IllegalArgumentException("Improper auto storage specified");
		}
		this.function = function;
	}

	@Override
	public Function getFunction() {
		return function;
	}

	private static String getAutoName(AutoParameterType autoParamType) {
		if (autoParamType == null) {
			throw new IllegalArgumentException("storage does not correspond to an auto-parameter");
		}
		return autoParamType.getDisplayName();
	}

	@Override
	public void setDataType(DataType type, VariableStorage storage, boolean force, SourceType source)
			throws InvalidInputException {
		throw new InvalidInputException("Auto-parameter may not be modified");
	}

	@Override
	public void setDataType(DataType type, SourceType source) throws InvalidInputException {
		throw new InvalidInputException("Auto-parameter may not be modified");
	}

	@Override
	public void setComment(String comment) {
		// Auto-parameter may not be modified
	}

	@Override
	public void setName(String name, SourceType source) throws InvalidInputException {
		throw new InvalidInputException("Auto-parameter may not be modified");
	}

}
