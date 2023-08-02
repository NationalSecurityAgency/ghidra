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

import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;

/**
 * The symbol table for traces.
 * 
 * <p>
 * Currently, functions are not supported, so effectively, the only symbol types possible in a trace
 * are: labels, namespaces, and classes. Global variables are partially implemented, but as they are
 * not finished, even in {@link Program}, they are not available in traces, either.
 * 
 * <p>
 * This manager supports a "fluid" API syntax. The methods on this manager narrow the scope in terms
 * of the symbol type. Each returns a view, the methods of which operate on that type specifically.
 * For example, to get the label at a specific address:
 * 
 * <pre>
 * trace.getSymbolManager().labels().getAt(0, null, addr, false);
 * </pre>
 */
public interface TraceSymbolManager {

	/**
	 * A comparator that sorts primary symbols first.
	 */
	static Comparator<TraceSymbol> PRIMALITY_COMPARATOR = (a, b) -> {
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

	/**
	 * Get the trace for this manager.
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get a symbol by its unique identifier.
	 * 
	 * <p>
	 * The identifier is only unique within this trace.
	 * 
	 * @param symbolID the id
	 * @return the symbol, or null
	 */
	TraceSymbol getSymbolByID(long symbolID);

	/**
	 * Get the trace's global namespace.
	 * 
	 * @return the global namespace
	 */
	TraceNamespaceSymbol getGlobalNamespace();

	/**
	 * Get a view of the labels in the trace.
	 * 
	 * @return the labels view
	 */
	TraceLabelSymbolView labels();

	/**
	 * Get a view of the namespaces in the trace.
	 * 
	 * @return the namespaces view
	 */
	TraceNamespaceSymbolView namespaces();

	/**
	 * Get a view of the classes in the trace.
	 * 
	 * @return the classes view
	 */
	TraceClassSymbolView classes();

	/**
	 * Get a view of all the namespaces (including classes) in the trace.
	 * 
	 * @return the all-namespaces view
	 */
	TraceSymbolView<? extends TraceNamespaceSymbol> allNamespaces();

	/**
	 * Get a view of all the symbols except labels in the trace.
	 * 
	 * <p>
	 * <b>NOTE:</b> This method is somewhat vestigial. At one point, functions were partially
	 * implemented, so this would have contained functions, variables, etc. As the manager now only
	 * supports labels, namespaces, and classes, this is essentially the same as
	 * {@link #allNamespaces()}.
	 * 
	 * @return the not-labels view
	 */
	TraceSymbolNoDuplicatesView<? extends TraceSymbol> notLabels();

	/**
	 * Get a view of all symbols in the trace.
	 * 
	 * @return the all-symbols view
	 */
	TraceSymbolView<? extends TraceSymbol> allSymbols();

	/**
	 * Get the set of unique symbol IDs that are added going from one snapshot to another.
	 * 
	 * @param from the first snapshot key
	 * @param to the second snapshot key
	 * @return the set of IDs absent in the first but present in the second
	 */
	Collection<Long> getIDsAdded(long from, long to);

	/**
	 * Get the set of unique symbol IDs that are removed going from one snapshot to another.
	 * 
	 * @param from the first snapshot key
	 * @param to the second snapshot key
	 * @return the set of IDs present in the first but absent in the second
	 */
	Collection<Long> getIDsRemoved(long from, long to);
}
