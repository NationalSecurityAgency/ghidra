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
package ghidra.app.plugin.core.navigation.locationreferences;

import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionDefinitionLocationDescriptor extends GenericDataTypeLocationDescriptor {

	private FunctionDefinition functionDefinition;

	FunctionDefinitionLocationDescriptor(ProgramLocation location, Program program,
			FunctionDefinition functionDefinition) {
		super(location, program, functionDefinition);

		this.functionDefinition = functionDefinition;
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		DataType myReturnType = functionDefinition.getReturnType();
		ParameterDefinition[] myParameters = functionDefinition.getArguments();

		FunctionManager functionManager = program.getFunctionManager();
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator symbols = symbolTable.getSymbols(functionDefinition.getName());

		// the definition could be applied in more than one namespace, so handle each application
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();

			if (!(symbol instanceof FunctionSymbol)) {
				continue;
			}
			FunctionSymbol functionSymbol = (FunctionSymbol) symbol;
			long symbolID = functionSymbol.getID();
			Function function = functionManager.getFunction(symbolID);

			FunctionSignature signature = function.getSignature(true);
			ParameterDefinition[] theirParameters = signature.getArguments();
			if (!isSameParamters(myParameters, theirParameters)) {
				continue;
			}

			if (!myReturnType.isEquivalent(signature.getReturnType())) {
				continue;
			}

			accumulator.add(new LocationReference(symbol.getAddress()));
		}
	}

	private boolean isSameParamters(ParameterDefinition[] myParameters,
			ParameterDefinition[] theirParameters) {
		if (theirParameters.length != myParameters.length) {
			return false;
		}

		for (int i = 0; i < myParameters.length; i++) {
			ParameterDefinition myDefinition = myParameters[i];
			ParameterDefinition theirDefinition = theirParameters[i];
			if (!myDefinition.isEquivalent(theirDefinition)) {
				return false;
			}
		}
		return true;
	}
}
