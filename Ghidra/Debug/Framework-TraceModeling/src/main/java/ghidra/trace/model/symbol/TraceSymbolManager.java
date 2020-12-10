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
package ghidra.trace.model.symbol;

import java.util.Collection;
import java.util.Comparator;

import ghidra.trace.model.Trace;

public interface TraceSymbolManager {

	static Comparator<TraceSymbol> PRIMALITY_COMPARATOR = (a, b) -> {
		boolean aFunc = a instanceof TraceFunctionSymbol;
		boolean bFunc = b instanceof TraceFunctionSymbol;
		if (aFunc && !bFunc) {
			return -1;
		}
		if (!aFunc && bFunc) {
			return 1;
		}
		boolean aPrim = a.isPrimary();
		boolean bPrim = b.isPrimary();
		if (aPrim && !bPrim) {
			return -1;
		}
		if (!aPrim && bPrim) {
			return 1;
		}
		return 0;
	};

	Trace getTrace();

	TraceSymbol getSymbolByID(long symbolID);

	TraceNamespaceSymbol getGlobalNamespace();

	TraceLabelSymbolView labels();

	TraceNamespaceSymbolView namespaces();

	TraceClassSymbolView classes();

	TraceFunctionSymbolView functions();

	TraceParameterSymbolView parameters();

	TraceLocalVariableSymbolView localVariables();

	TraceGlobalVariableSymbolView globalVariables();

	/**
	 * TODO: Document me
	 * 
	 * Note because functions are namespaces, and duplicate function names are allowed, this
	 * composed view may have duplicate names.
	 * 
	 * @return
	 */
	TraceSymbolView<? extends TraceNamespaceSymbol> allNamespaces();

	TraceSymbolWithAddressNoDuplicatesView<? extends TraceVariableSymbol> allLocals();

	TraceSymbolWithAddressNoDuplicatesView<? extends TraceSymbol> allVariables();

	TraceSymbolWithLocationView<? extends TraceSymbol> labelsAndFunctions();

	TraceSymbolNoDuplicatesView<? extends TraceSymbol> notLabelsNorFunctions();

	TraceSymbolView<? extends TraceSymbol> allSymbols();

	Collection<Long> getIDsAdded(long from, long to);

	Collection<Long> getIDsRemoved(long from, long to);
}
