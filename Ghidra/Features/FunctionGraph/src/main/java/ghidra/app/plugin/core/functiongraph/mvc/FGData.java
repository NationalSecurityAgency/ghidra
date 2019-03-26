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
package ghidra.app.plugin.core.functiongraph.mvc;

import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * An object that represents data for the FunctionGraph plugin.  This object has necessary
 * information to create a Graph.
 */
public class FGData {

	private FunctionGraph graph;
	private final String errorMessage;
	private final Function function;

	public FGData(Function function, FunctionGraph graph) {
		this(function, graph, null);
	}

	public FGData(Function function, FunctionGraph graph, String errorMessage) {
		this.function = function;
		this.graph = graph;
		this.errorMessage = errorMessage;
	}

	public FunctionGraph getFunctionGraph() {
		return graph;
	}

	public boolean hasResults() {
		return true;
	}

	public String getMessage() {
		return errorMessage;
	}

	public boolean containsLocation(ProgramLocation location) {
		if (!hasResults()) {
			return false;
		}

		if (location == null) {
			return false;
		}

		Address address = location.getAddress();
		return function.getBody().contains(address);
	}

	public boolean containsSelection(ProgramSelection selection) {
		if (!hasResults()) {
			return false;
		}

		if (selection == null || selection.isEmpty()) {
			// we 'contain' the empty and null selections (empty to match set theory and null to
			// allow null selections to be set upon us (for clearing)).
			return true;
		}

		return function.getBody().intersects(selection);
	}

	public Function getFunction() {
		return function;
	}

	public FunctionGraphOptions getOptions() {
		if (graph == null) {
			return null;
		}
		return graph.getOptions();
	}

	public void dispose() {
		if (graph == null) {
			return;
		}
		graph.dispose();
		graph = null;
	}

	@Override
	public String toString() {
		return "FunctionGraphData[" + function.getName() + "]";
	}
}
