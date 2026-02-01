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
package ghidra.bsfv;

import docking.Tool;
import ghidra.service.graph.*;
import ghidra.util.HelpLocation;

/**
 * This class is the {@link GraphDisplayOptions} for BSim Feature Graphs.
 */
public class BSimFeatureGraphDisplayOptions extends GraphDisplayOptions {

	public BSimFeatureGraphDisplayOptions(GraphType graphType, Tool tool) {
		super(graphType, tool,
			new HelpLocation("BSimFeatureVisualizerPlugin", "Visualizing_BSim_Features"));
	}

	@Override
	protected void initializeDefaults() {
		setDefaultVertexColor("color.bsim.graph.vertex.default");
		setDefaultEdgeColor("color.bsim.graph.edge.default");
		setVertexSelectionColor("color.bsim.graph.vertex.selection");
		setEdgeSelectionColor("color.bsim.graph.edge.selection");

		setDefaultVertexShape(VertexShape.ELLIPSE);
		setDefaultLayoutAlgorithmName("Hierarchical MinCross Top Down");
		setUsesIcons(false);
		setLabelPosition(GraphLabelPosition.EAST);

		configureVertexType(BSimFeatureGraphType.PCODE_OP_VERTEX, VertexShape.ELLIPSE,
			"color.bsim.graph.dataflow.vertex.pcode.op");
		configureVertexType(BSimFeatureGraphType.BASE_VARNODE_VERTEX, VertexShape.ELLIPSE,
			"color.bsim.graph.dataflow.vertex.base");
		configureVertexType(BSimFeatureGraphType.SECONDARY_BASE_VARNODE_VERTEX, VertexShape.ELLIPSE,
			"color.bsim.graph.dataflow.vertex.base.2");
		configureVertexType(BSimFeatureGraphType.COLLAPSED_OP, VertexShape.ELLIPSE,
			"color.bsim.graph.dataflow.vertex.pcode.op.collapsed");
		configureVertexType(BSimFeatureGraphType.COLLAPSED_VARNODE, VertexShape.ELLIPSE,
			"color.bsim.graph.dataflow.vertex.varnode.collapsed");

		configureVertexType(BSimFeatureGraphType.BASE_BLOCK_VERTEX, VertexShape.RECTANGLE,
			"color.bsim.graph.controlflow.vertex.base");
		configureVertexType(BSimFeatureGraphType.PARENT_BLOCK_VERTEX, VertexShape.RECTANGLE,
			"color.bsim.graph.controlflow.vertex.parent");
		configureVertexType(BSimFeatureGraphType.GRANDPARENT_BLOCK_VERTEX, VertexShape.RECTANGLE,
			"color.bsim.graph.controlflow.vertex.grandparent");
		configureVertexType(BSimFeatureGraphType.SIBLING_BLOCK_VERTEX, VertexShape.RECTANGLE,
			"color.bsim.graph.controlflow.vertex.sibling");
		configureVertexType(BSimFeatureGraphType.CHILD_BLOCK_VERTEX, VertexShape.RECTANGLE,
			"color.bsim.graph.controlflow.vertex.child");
		configureVertexType(BSimFeatureGraphType.BSIM_NEIGHBOR_VERTEX, VertexShape.RECTANGLE,
			"color.bsim.graph.controlflow.vertex.neighbor");

		configureEdgeType(BSimFeatureGraphType.TRUE_EDGE, "color.bsim.graph.edge.controlflow.true");
		configureEdgeType(BSimFeatureGraphType.FALSE_EDGE,
			"color.bsim.graph.edge.controlflow.false");
		configureEdgeType(BSimFeatureGraphType.COLLAPSED_IN,
			"color.bsim.graph.edge.dataflow.in.collapsed");
		configureEdgeType(BSimFeatureGraphType.COLLAPSED_OUT,
			"color.bsim.graph.edge.dataflow.out.collapsed");
		configureEdgeType(BSimFeatureGraphType.DATAFLOW_IN, "color.bsim.graph.edge.dataflow.in");
		configureEdgeType(BSimFeatureGraphType.DATAFLOW_OUT, "color.bsim.graph.edge.dataflow.out");
	}

}
