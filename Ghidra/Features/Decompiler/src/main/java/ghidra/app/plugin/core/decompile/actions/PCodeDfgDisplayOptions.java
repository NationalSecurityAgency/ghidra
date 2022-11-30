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
package ghidra.app.plugin.core.decompile.actions;

import static ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphType.*;
import static ghidra.service.graph.VertexShape.*;

import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.*;

/** 
 * {@link GraphDisplayOptions} for {@link PCodeDfgGraphType}
 */
public class PCodeDfgDisplayOptions extends GraphDisplayOptions {
	public static final String SHAPE_ATTRIBUTE = "Shape";

	// @formatter:off
	private static final String BG_VERTEX_DEFAULT = "color.bg.decompiler.pcode.dfg.vertex.default";
	private static final String BG_VERTEX_SELECTED ="color.bg.decompiler.pcode.dfg.vertex.selected";
	private static final String BG_VERTEX_CONSTANT ="color.bg.decompiler.pcode.dfg.vertex.constant";
	private static final String BG_VERTEX_REGISTER ="color.bg.decompiler.pcode.dfg.vertex.register";
	private static final String BG_VERTEX_UNIQUE ="color.bg.decompiler.pcode.dfg.vertex.unique";
	private static final String BG_VERTEX_PERSISTENT ="color.bg.decompiler.pcode.dfg.vertex.persistent";
	private static final String BG_VERTEX_ADDRESS_TIED ="color.bg.decompiler.pcode.dfg.vertex.address.tied";
	private static final String BG_VERTEX_OP ="color.bg.decompiler.pcode.dfg.vertex.op";

	private static final String BG_EDGE_DEFAULT ="color.bg.decompiler.pcode.dfg.edge.default";
	private static final String BG_EDGE_SELECTED ="color.bg.decompiler.pcode.dfg.edge.selected";
	private static final String BG_EDGE_WITHIN_BLOCK ="color.bg.decompiler.pcode.dfg.edge.within.block";
	private static final String BG_EDGE_BETWEEN_BLOCKS ="color.bg.decompiler.pcode.dfg.edge.between.blocks";
	// @formatter:on

	/**
	 * constructor
	 * @param tool if non-null, will load values from tool options
	 */
	public PCodeDfgDisplayOptions(PluginTool tool) {
		super(new PCodeDfgGraphType(), tool);
	}

	@Override
	protected void initializeDefaults() {
		setDefaultVertexShape(ELLIPSE);
		setDefaultVertexColor(BG_VERTEX_DEFAULT);
		setDefaultEdgeColor(BG_EDGE_DEFAULT);
		setVertexSelectionColor(BG_VERTEX_SELECTED);
		setEdgeSelectionColor(BG_EDGE_SELECTED);
		setDefaultLayoutAlgorithmName(LayoutAlgorithmNames.MIN_CROSS_COFFMAN_GRAHAM);
		setUsesIcons(false);
		setArrowLength(15);
		setLabelPosition(GraphLabelPosition.SOUTH);
		setVertexShapeOverrideAttributeKey(SHAPE_ATTRIBUTE);
		setMaxNodeCount(1000);

		configureVertexType(DEFAULT_VERTEX, VertexShape.ELLIPSE, BG_VERTEX_DEFAULT);
		configureVertexType(CONSTANT, VertexShape.ELLIPSE, BG_VERTEX_CONSTANT);
		configureVertexType(REGISTER, VertexShape.ELLIPSE, BG_VERTEX_REGISTER);
		configureVertexType(UNIQUE, VertexShape.ELLIPSE, BG_VERTEX_UNIQUE);
		configureVertexType(PERSISTENT, VertexShape.ELLIPSE, BG_VERTEX_PERSISTENT);
		configureVertexType(ADDRESS_TIED, VertexShape.ELLIPSE, BG_VERTEX_ADDRESS_TIED);
		configureVertexType(OP, VertexShape.ELLIPSE, BG_VERTEX_OP);

		configureEdgeType(DEFAULT_EDGE, BG_EDGE_DEFAULT);
		configureEdgeType(WITHIN_BLOCK, BG_EDGE_WITHIN_BLOCK);
		configureEdgeType(BETWEEN_BLOCKS, BG_EDGE_BETWEEN_BLOCKS);

		setFont("font.decompiler.pcode.dfg");
	}
}
