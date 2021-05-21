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
package ghidra.graph.program;

import java.util.*;

import docking.action.builder.ActionBuilder;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.*;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskLauncher;

/*
 * Listener for a GraphDisplay holding a Reference graph. Allows for the extension of the
 * graph from a specified node
 */
public class DataReferenceGraphDisplayListener extends AddressBasedGraphDisplayListener {

	private int stepDepth;

	public DataReferenceGraphDisplayListener(PluginTool tool, GraphDisplay display, Program program,
			int depth) {
		super(tool, program, display);

		stepDepth = depth;

		HelpLocation helpLoc = new HelpLocation("ProgramGraphPlugin", "Add_References");
		display.addAction(new ActionBuilder("Add To/From References", "Data Graph")
				.popupMenuPath("Add Bidirectional References For Selection")
				.withContext(VertexGraphActionContext.class)
				.helpLocation(helpLoc)
				.onAction(this::addToGraph)
				.build());
		display.addAction(new ActionBuilder("Add To References", "Data Graph")
				.popupMenuPath("Add References To Selection")
				.withContext(VertexGraphActionContext.class)
				.helpLocation(helpLoc)
				.onAction(this::addTosToGraph)
				.build());
		display.addAction(new ActionBuilder("Add From References", "Data Graph")
				.popupMenuPath("Add References From Selection")
				.withContext(VertexGraphActionContext.class)
				.helpLocation(helpLoc)
				.onAction(this::addFromsToGraph)
				.build());
	}

	private void addToGraph(VertexGraphActionContext context) {
		doAdd(context, DataReferenceGraph.Directions.BOTH_WAYS);
	}

	private void addTosToGraph(VertexGraphActionContext context) {
		doAdd(context, DataReferenceGraph.Directions.TO_ONLY);
	}

	private void addFromsToGraph(VertexGraphActionContext context) {
		doAdd(context, DataReferenceGraph.Directions.FROM_ONLY);
	}

	private void doAdd(VertexGraphActionContext context, DataReferenceGraph.Directions direction) {
		AddressSet addresses = new AddressSet();
		for (AttributedVertex vertex : context.getSelectedVertices()) {
			addresses.add(getAddress(vertex));
		}
		DataReferenceGraphTask task = new DataReferenceGraphTask(tool, program, addresses,
			graphDisplay, stepDepth, direction);
		new TaskLauncher(task, tool.getToolFrame());

		/* I don't know why the selection was going all wonky, but reset it */
		graphDisplay.selectVertices(context.getSelectedVertices(), EventTrigger.INTERNAL_ONLY);
	}

	@Override
	public GraphDisplayListener cloneWith(GraphDisplay newDisplay) {
		return new DataReferenceGraphDisplayListener(tool, newDisplay, program, stepDepth);
	}

	@Override
	protected Set<AttributedVertex> getVertices(AddressSetView selection) {
		if (selection.isEmpty()) {
			return Collections.emptySet();
		}

		Set<AttributedVertex> vertices = new HashSet<>();
		DataReferenceGraph graph = (DataReferenceGraph) graphDisplay.getGraph();
		for (AddressRange range : selection) {
			for (Address address : range) {
				AttributedVertex vertex = graph.getVertex(graph.makeName(address));
				if (vertex != null) {
					vertices.add(vertex);
				}
			}
		}

		return vertices;
	}

	@Override
	protected AddressSet getAddresses(Set<AttributedVertex> vertexIds) {
		AddressSet addrSet = new AddressSet();

		for (AttributedVertex vertex : vertexIds) {
			Address addr = getAddress(vertex.getName());
			if (addr != null) {
				addrSet.add(addr);
			}
		}
		return addrSet;
	}

	@Override
	protected Address getAddress(String vertexIdString) {
		AttributedVertex vertex = graphDisplay.getGraph().getVertex(vertexIdString);
		return program.getAddressFactory()
				.getAddress(vertex.getAttribute(DataReferenceGraph.ADDRESS_ATTRIBUTE));
	}

	@Override
	protected String getVertexId(Address address) {
		DataReferenceGraph graph = (DataReferenceGraph) graphDisplay.getGraph();
		return graph.makeName(address);
	}
}
