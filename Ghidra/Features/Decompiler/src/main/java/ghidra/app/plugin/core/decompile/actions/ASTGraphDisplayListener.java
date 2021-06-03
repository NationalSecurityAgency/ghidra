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

import static ghidra.app.plugin.core.decompile.actions.ASTGraphTask.GraphType.*;

import java.util.*;

import ghidra.app.plugin.core.decompile.actions.ASTGraphTask.GraphType;
import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.service.graph.*;
import ghidra.util.exception.AssertException;

/**
 * Listener for when an AST graph's nodes are selected.
 */
public class ASTGraphDisplayListener extends AddressBasedGraphDisplayListener {
	private HighFunction hfunction;
	private GraphType graphType;

	ASTGraphDisplayListener(PluginTool tool, GraphDisplay display, HighFunction hfunction,
			GraphType graphType) {
		super(tool, hfunction.getFunction().getProgram(), display);
		this.hfunction = hfunction;
		this.graphType = graphType;
	}

	@Override
	protected Set<AttributedVertex> getVertices(AddressSetView selection) {
		if (graphType != CONTROL_FLOW_GRAPH) {
			return null;
		}
		Set<AttributedVertex> vertices = new HashSet<>();
		List<PcodeBlockBasic> blocks = hfunction.getBasicBlocks();
		for (PcodeBlockBasic block : blocks) {
			Address start = block.getStart();
			Address stop = block.getStop();
			if (selection.intersects(start, stop)) {
				String id = Integer.toString(block.getIndex());
				AttributedVertex vertex = graphDisplay.getGraph().getVertex(id);
				if (vertex != null) {
					vertices.add(vertex);
				}
			}
		}
		return vertices;
	}

	@Override
	protected AddressSet getAddresses(Set<AttributedVertex> vertices) {
		if (graphType != CONTROL_FLOW_GRAPH) {
			return null;
		}

		AddressSet set = new AddressSet();
		List<PcodeBlockBasic> blocks = hfunction.getBasicBlocks();
		for (AttributedVertex vertex : vertices) {
			try {
				int index = Integer.parseInt(vertex.getId());
				PcodeBlockBasic block = blocks.get(index);
				Address start = block.getStart();
				set.addRange(start, block.getStop());
			}
			catch (NumberFormatException e) {
				// continue
			}
		}
		return set;
	}

	@Override
	protected String getVertexId(Address address) {
		if (graphType != CONTROL_FLOW_GRAPH) {
			return null;
		}
		List<PcodeBlockBasic> blocks = hfunction.getBasicBlocks();
		for (PcodeBlockBasic block : blocks) {
			Address start = block.getStart();
			Address stop = block.getStop();
			if (address.compareTo(start) >= 0 && address.compareTo(stop) <= 0) {
				return Integer.toString(block.getIndex());
			}
		}
		return super.getVertexId(address);
	}

	@Override
	protected Address getAddress(AttributedVertex vertex) {
		List<PcodeBlockBasic> blocks = hfunction.getBasicBlocks();

		try {
			int index = Integer.parseInt(vertex.getId());
			PcodeBlockBasic block = blocks.get(index);
			return block.getStart();
		}
		catch (NumberFormatException e) {
			throw new AssertException("Bad vertex id, expected a number but got " + vertex.getId());
		}
	}

	@Override
	public GraphDisplayListener cloneWith(GraphDisplay display) {
		return new ASTGraphDisplayListener(tool, graphDisplay, hfunction, graphType);
	}

}
