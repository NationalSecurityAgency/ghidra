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
		setDefaultVertexColor("color.bg.plugin.programgraph.vertex.default");
		setDefaultEdgeColor("color.bg.plugin.programgraph.edge.default");
		setVertexSelectionColor("color.bg.plugin.programgraph.vertex.selection");
		setEdgeSelectionColor("color.bg.plugin.programgraph.edge.selection");
		setFavoredEdgeType(FALL_THROUGH);

		//@formatter:off
		configureVertexType(BODY, RECTANGLE, "color.bg.plugin.programgraph.vertex.body");
		configureVertexType(ENTRY, TRIANGLE_DOWN, "color.bg.plugin.programgraph.vertex.entry");
		configureVertexType(EXIT, TRIANGLE_UP, "color.bg.plugin.programgraph.vertex.exit");
		configureVertexType(SWITCH, DIAMOND, "color.bg.plugin.programgraph.vertex.switch");
		configureVertexType(EXTERNAL, RECTANGLE, "color.bg.plugin.programgraph.vertex.external");
		configureVertexType(BAD, ELLIPSE, "color.bg.plugin.programgraph.vertex.bad");
		configureVertexType(DATA, ELLIPSE, "color.bg.plugin.programgraph.vertex.data");
		configureVertexType(ENTRY_NEXUS, ELLIPSE, "color.bg.plugin.programgraph.vertex.entry.nexus");
		configureVertexType(INSTRUCTION, VertexShape.HEXAGON, "color.bg.plugin.programgraph.vertex.instruction");
		configureVertexType(STACK, RECTANGLE, "color.bg.plugin.programgraph.vertex.stack");

		configureEdgeType(ENTRY_EDGE, "color.bg.plugin.programgraph.edge.entry");
		configureEdgeType(FALL_THROUGH, "color.bg.plugin.programgraph.edge.fall.through");
		configureEdgeType(UNCONDITIONAL_JUMP, "color.bg.plugin.programgraph.edge.jump.unconditional");
		configureEdgeType(UNCONDITIONAL_CALL, "color.bg.plugin.programgraph.edge.call.unconditional");
		configureEdgeType(TERMINATOR, "color.bg.plugin.programgraph.edge.terminator");
		configureEdgeType(JUMP_TERMINATOR, "color.bg.plugin.programgraph.edge.jump.terminator");
		configureEdgeType(INDIRECTION, "color.bg.plugin.programgraph.edge.indirection");

		configureEdgeType(CONDITIONAL_JUMP, "color.bg.plugin.programgraph.edge.jump.conditional");
		configureEdgeType(CONDITIONAL_CALL, "color.bg.plugin.programgraph.edge.call.conditional");
		configureEdgeType(CONDITIONAL_TERMINATOR, "color.bg.plugin.programgraph.edge.conditional.terminator");
		configureEdgeType(CONDITIONAL_CALL_TERMINATOR, "color.bg.plugin.programgraph.edge.call.conditional.terminator");

		configureEdgeType(COMPUTED_JUMP, "color.bg.plugin.programgraph.edge.jump.computed");
		configureEdgeType(COMPUTED_CALL, "color.bg.plugin.programgraph.edge.call.computed");
		configureEdgeType(COMPUTED_CALL_TERMINATOR, "color.bg.plugin.programgraph.edge.call.computed.terminator");

		configureEdgeType(CONDITIONAL_COMPUTED_CALL, "color.bg.plugin.programgraph.edge.call.conditional.computed");
		configureEdgeType(CONDITIONAL_COMPUTED_JUMP, "color.bg.plugin.programgraph.edge.jump.conitional.computed");

		configureEdgeType(CALL_OVERRIDE_UNCONDITIONAL, "color.bg.plugin.programgraph.edge.call.unconditional.override");
		configureEdgeType(JUMP_OVERRIDE_UNCONDITIONAL, "color.bg.plugin.programgraph.edge.jump.unconditional.override");
		configureEdgeType(CALLOTHER_OVERRIDE_CALL, "color.bg.plugin.programgraph.edge.call.callother.override");
		configureEdgeType(CALLOTHER_OVERRIDE_JUMP, "color.bg.plugin.programgraph.edge.jump.callother.override");

		configureEdgeType(READ, "color.bg.plugin.programgraph.edge.read");
		configureEdgeType(WRITE, "color.bg.plugin.programgraph.edge.write");
		configureEdgeType(READ_WRITE, "color.bg.plugin.programgraph.edge.read.write");
		configureEdgeType(UNKNOWN_DATA, "color.bg.plugin.programgraph.edge.data.unknown");
		configureEdgeType(EXTERNAL_REF, "color.bg.plugin.programgraph.edge.external.ref");

		configureEdgeType(READ_INDIRECT, "color.bg.plugin.programgraph.edge.read.indirect");
		configureEdgeType(WRITE_INDIRECT, "color.bg.plugin.programgraph.edge.write.indirect");
		configureEdgeType(READ_WRITE_INDIRECT, "color.bg.plugin.programgraph.edge.read.write.indirect");
		configureEdgeType(DATA_INDIRECT, "color.bg.plugin.programgraph.edge.data.indirect");

		configureEdgeType(PARAM, "color.bg.plugin.programgraph.edge.param");
		configureEdgeType(THUNK, "color.bg.plugin.programgraph.edge.thunk");
		
		setFont("font.plugin.programgraph");
		//@formatter:on
	}
}
