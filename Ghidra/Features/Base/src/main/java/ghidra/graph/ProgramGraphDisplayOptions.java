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
package ghidra.graph;

import static ghidra.graph.ProgramGraphType.*;
import static ghidra.service.graph.VertexShape.*;

import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.GraphDisplayOptions;
import ghidra.service.graph.VertexShape;
import ghidra.util.WebColors;

/** 
 * {@link GraphDisplayOptions} for {@link ProgramGraphType}
 */
public class ProgramGraphDisplayOptions extends GraphDisplayOptions {

	/**
	 * constructor
	 * @param graphType the specific ProgramGraphType subclass for these options
	 * @param tool if non-null, will load values from tool options
	 */
	public ProgramGraphDisplayOptions(ProgramGraphType graphType, PluginTool tool) {
		super(graphType, tool);
	}

	@Override
	protected void initializeDefaults() {
		setDefaultVertexShape(ELLIPSE);
		setDefaultVertexColor(WebColors.RED);
		setDefaultEdgeColor(WebColors.RED);
		setFavoredEdgeType(FALL_THROUGH);

		configureVertexType(BODY, RECTANGLE, WebColors.BLUE);
		configureVertexType(ENTRY, TRIANGLE_DOWN, WebColors.DARK_ORANGE);
		configureVertexType(EXIT, TRIANGLE_UP, WebColors.DARK_MAGENTA);
		configureVertexType(SWITCH, DIAMOND, WebColors.DARK_CYAN);
		configureVertexType(EXTERNAL, RECTANGLE, WebColors.DARK_GREEN);
		configureVertexType(BAD, ELLIPSE, WebColors.RED);
		configureVertexType(DATA, ELLIPSE, WebColors.PINK);
		configureVertexType(ENTRY_NEXUS, ELLIPSE, WebColors.WHEAT);
		configureVertexType(INSTRUCTION, VertexShape.HEXAGON, WebColors.BLUE);
		configureVertexType(STACK, RECTANGLE, WebColors.GREEN);

		configureEdgeType(ENTRY_EDGE, WebColors.GRAY);
		configureEdgeType(FALL_THROUGH, WebColors.BLUE);
		configureEdgeType(UNCONDITIONAL_JUMP, WebColors.DARK_GREEN);
		configureEdgeType(UNCONDITIONAL_CALL, WebColors.DARK_ORANGE);
		configureEdgeType(TERMINATOR, WebColors.PURPLE);
		configureEdgeType(JUMP_TERMINATOR, WebColors.PURPLE);
		configureEdgeType(INDIRECTION, WebColors.PINK);

		configureEdgeType(CONDITIONAL_JUMP, WebColors.DARK_GOLDENROD);
		configureEdgeType(CONDITIONAL_CALL, WebColors.DARK_ORANGE);
		configureEdgeType(CONDITIONAL_TERMINATOR, WebColors.PURPLE);
		configureEdgeType(CONDITIONAL_CALL_TERMINATOR, WebColors.PURPLE);

		configureEdgeType(COMPUTED_JUMP, WebColors.CYAN);
		configureEdgeType(COMPUTED_CALL, WebColors.CYAN);
		configureEdgeType(COMPUTED_CALL_TERMINATOR, WebColors.PURPLE);

		configureEdgeType(CONDITIONAL_COMPUTED_CALL, WebColors.CYAN);
		configureEdgeType(CONDITIONAL_COMPUTED_JUMP, WebColors.CYAN);

		configureEdgeType(CALL_OVERRIDE_UNCONDITIONAL, WebColors.RED);
		configureEdgeType(JUMP_OVERRIDE_UNCONDITIONAL, WebColors.RED);
		configureEdgeType(CALLOTHER_OVERRIDE_CALL, WebColors.RED);
		configureEdgeType(CALLOTHER_OVERRIDE_JUMP, WebColors.RED);

		configureEdgeType(READ, WebColors.GREEN);
		configureEdgeType(WRITE, WebColors.RED);
		configureEdgeType(READ_WRITE, WebColors.DARK_GOLDENROD);
		configureEdgeType(UNKNOWN_DATA, WebColors.BLACK);
		configureEdgeType(EXTERNAL_REF, WebColors.PURPLE);

		configureEdgeType(READ_INDIRECT, WebColors.DARK_GREEN);
		configureEdgeType(WRITE_INDIRECT, WebColors.DARK_RED);
		configureEdgeType(READ_WRITE_INDIRECT, WebColors.BROWN);
		configureEdgeType(DATA_INDIRECT, WebColors.DARK_ORANGE);

		configureEdgeType(PARAM, WebColors.CYAN);
		configureEdgeType(THUNK, WebColors.BLUE);

	}
}
