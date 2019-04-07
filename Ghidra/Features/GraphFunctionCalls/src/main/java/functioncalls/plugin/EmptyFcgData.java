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

import functioncalls.graph.*;
import ghidra.graph.viewer.GraphPerspectiveInfo;
import ghidra.program.model.listing.Function;

/**
 * An empty data that is used to avoid null checks
 */
public class EmptyFcgData implements FcgData {

	@Override
	public Function getFunction() {
		throw new UnsupportedOperationException("Empty data has no function");
	}

	@Override
	public boolean isFunction(Function f) {
		return false;
	}

	@Override
	public FunctionCallGraph getGraph() {
		throw new UnsupportedOperationException("Empty data has no graph");
	}

	@Override
	public FunctionEdgeCache getFunctionEdgeCache() {
		throw new UnsupportedOperationException("Empty data has no function edge cache");
	}

	@Override
	public boolean hasResults() {
		return false;
	}

	@Override
	public void dispose() {
		// we are empty; nothing to do
	}

	@Override
	public boolean isInitialized() {
		return false;
	}

	@Override
	public GraphPerspectiveInfo<FcgVertex, FcgEdge> getGraphPerspective() {
		throw new UnsupportedOperationException("Empty data does not need view information");
	}

	@Override
	public void setGraphPerspective(GraphPerspectiveInfo<FcgVertex, FcgEdge> info) {
		throw new UnsupportedOperationException("Empty data does not need view information");
	}
}
