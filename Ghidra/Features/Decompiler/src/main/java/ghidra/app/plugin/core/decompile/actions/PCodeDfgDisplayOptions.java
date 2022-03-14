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
import ghidra.util.WebColors;

/** 
 * {@link GraphDisplayOptions} for {@link PCodeDfgGraphType}
 */
public class PCodeDfgDisplayOptions extends GraphDisplayOptions {
	public static final String SHAPE_ATTRIBUTE = "Shape";

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
		setDefaultVertexColor(WebColors.RED);
		setDefaultEdgeColor(WebColors.NAVY);
		setVertexSelectionColor(WebColors.DEEP_PINK);
		setEdgeSelectionColor(WebColors.DEEP_PINK);
		setDefaultLayoutAlgorithmName(LayoutAlgorithmNames.MIN_CROSS_COFFMAN_GRAHAM);
		setUsesIcons(false);
		setArrowLength(15);
		setLabelPosition(GraphLabelPosition.SOUTH);
		setVertexShapeOverrideAttributeKey(SHAPE_ATTRIBUTE);
		setMaxNodeCount(1000);

		configureVertexType(DEFAULT_VERTEX, VertexShape.ELLIPSE, WebColors.RED);
		configureVertexType(CONSTANT, VertexShape.ELLIPSE, WebColors.DARK_GREEN);
		configureVertexType(REGISTER, VertexShape.ELLIPSE, WebColors.NAVY);
		configureVertexType(UNIQUE, VertexShape.ELLIPSE, WebColors.BLACK);
		configureVertexType(PERSISTENT, VertexShape.ELLIPSE, WebColors.DARK_ORANGE);
		configureVertexType(ADDRESS_TIED, VertexShape.ELLIPSE, WebColors.ORANGE);
		configureVertexType(OP, VertexShape.ELLIPSE, WebColors.RED);

		configureEdgeType(DEFAULT_EDGE, WebColors.BLUE);
		configureEdgeType(WITHIN_BLOCK, WebColors.BLACK);
		configureEdgeType(BETWEEN_BLOCKS, WebColors.RED);
	}
}
