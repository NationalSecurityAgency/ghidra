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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import ghidra.framework.options.Options;
import ghidra.util.HelpLocation;

/**
 * Options for the {@link DecompilerNestedLayout}
 */
public class DNLayoutOptions implements FGLayoutOptions {

	private static final String HELP_ANCHOR =
		DecompilerNestedLayoutProvider.LAYOUT_NAME + "_Options";
	private static final String USE_EDGE_ROUTING_AROUND_VERTICES_KEY =
		"Route Edges Around Vertices";
	private static final String USE_EDGE_ROUTING_AROUND_VERTICES_DESCRIPTION = "Signals that " +
		"edges should be routed around any intersecting vertex.  When toggled off, edges will " +
		"pass through any intersecting vertices.";

	private static final String DIM_RETURN_EDGES_KEY = "Use Dim Return Edges";
	private static final String DIM_RETURN_EDGES_DESCRIPTION =
		"Signals to lighten the default return edges.";

	private boolean useEdgeRoutingAroundVertices;
	private boolean useDimmedReturnEdges = true;

	@Override
	public void registerOptions(Options options) {

		HelpLocation help = new HelpLocation(OWNER, HELP_ANCHOR);

		options.registerOption(USE_EDGE_ROUTING_AROUND_VERTICES_KEY, useEdgeRoutingAroundVertices,
			help, USE_EDGE_ROUTING_AROUND_VERTICES_DESCRIPTION);

		options.registerOption(DIM_RETURN_EDGES_KEY, useDimmedReturnEdges, help,
			DIM_RETURN_EDGES_DESCRIPTION);
	}

	@Override
	public void loadOptions(Options options) {
		useEdgeRoutingAroundVertices =
			options.getBoolean(USE_EDGE_ROUTING_AROUND_VERTICES_KEY, useEdgeRoutingAroundVertices);

		useDimmedReturnEdges = options.getBoolean(DIM_RETURN_EDGES_KEY, useDimmedReturnEdges);

	}

	public boolean useEdgeRoutingAroundVertices() {
		return useEdgeRoutingAroundVertices;
	}

	public boolean useDimmedReturnEdges() {
		return useDimmedReturnEdges;
	}

	@Override
	public boolean optionChangeRequiresRelayout(String optionName) {
		// format: 'Nested Code Layout.Route Edges....'
		return optionName.endsWith(USE_EDGE_ROUTING_AROUND_VERTICES_KEY) ||
			optionName.endsWith(DIM_RETURN_EDGES_KEY);
	}
}
