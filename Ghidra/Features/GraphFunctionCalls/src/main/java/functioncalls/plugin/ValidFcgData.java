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
package functioncalls.plugin;

import java.util.Objects;

import functioncalls.graph.*;
import ghidra.graph.viewer.GraphPerspectiveInfo;
import ghidra.program.model.listing.Function;

/**
 * A simple class that is used to cache graph data for a given function
 */
public class ValidFcgData implements FcgData {

	private Function function;
	private FunctionCallGraph graph;
	private GraphPerspectiveInfo<FcgVertex, FcgEdge> perspectiveInfo;

	/** Contains all known edges, even those not showing in the graph */
	private FunctionEdgeCache allEdgesByFunction = new FunctionEdgeCache();

	ValidFcgData(Function function, FunctionCallGraph graph) {
		this.function = Objects.requireNonNull(function);
		this.graph = Objects.requireNonNull(graph);
	}

	@Override
	public Function getFunction() {
		return function;
	}

	@Override
	public boolean isFunction(Function f) {
		return function.equals(f);
	}

	@Override
	public FunctionCallGraph getGraph() {
		return graph;
	}

	@Override
	public FunctionEdgeCache getFunctionEdgeCache() {
		return allEdgesByFunction;
	}

	@Override
	public boolean hasResults() {
		return true; // this object is always considered valid; use EmptyFcgData for bad Functions
	}

	@Override
	public boolean isInitialized() {
		return !graph.isEmpty();
	}

	@Override
	public void dispose() {
		graph.dispose();
	}

	@Override
	public GraphPerspectiveInfo<FcgVertex, FcgEdge> getGraphPerspective() {
		return perspectiveInfo;
	}

	@Override
	public void setGraphPerspective(GraphPerspectiveInfo<FcgVertex, FcgEdge> info) {
		this.perspectiveInfo = info;
	}
}
