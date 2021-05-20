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

import docking.widgets.EventTrigger;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/*
 * Task for creating and displaying a data reference graph
 */
public class DataReferenceGraphTask extends Task {

	private String graphTitle;
	private GraphDisplayProvider graphProvider;
	private boolean reuseGraph;
	private boolean appendGraph;
	private PluginTool tool;
	private Program program;
	private int totalMaxDepth;
	private int maxLabelLength;
	private ProgramLocation location;
	private DataReferenceGraph.Directions direction;
	private AddressSet addresses;
	private GraphDisplay display;

	/*
	 * Constructor intended for creating a new graph
	 */
	public DataReferenceGraphTask(boolean reuseGraph, boolean appendToGraph, PluginTool tool,
			ProgramSelection selection, ProgramLocation location,
			GraphDisplayProvider graphProvider, int maxDepth, int maxLines,
			DataReferenceGraph.Directions direction) {
		super("Graph Data References", true, false, true);

		this.reuseGraph = reuseGraph;
		this.appendGraph = appendToGraph;
		this.tool = tool;
		this.graphProvider = graphProvider;
		this.program = location.getProgram();
		this.graphTitle = "Data references for: ";
		this.totalMaxDepth = maxDepth;
		this.maxLabelLength = maxLines;
		this.location = location;
		this.direction = direction;
		this.display = null;
		graphTitle = graphTitle + location.getAddress().toString();

		Address locationAddress = location.getAddress();
		addresses = new AddressSet(locationAddress);
		if ((selection != null) && (selection.contains(locationAddress))) {
			addresses.add(selection);
		}
		else {
			/* grab current address and the code unit it is part of so we don't miss stuff assigned to say the structure */
			Address unitAddress =
				program.getListing().getCodeUnitContaining(locationAddress).getAddress();
			addresses.add(unitAddress);
		}
	}

	/*
	 * constructor intended for extending a graph in the same display
	 */
	public DataReferenceGraphTask(PluginTool tool, Program program, AddressSet addresses,
			GraphDisplay display, int maxDepth, DataReferenceGraph.Directions direction) {
		super("Graph Data References", true, false, true);

		this.reuseGraph = true;
		this.appendGraph = true;
		this.tool = tool;
		this.display = display;
		this.program = program;
		this.graphTitle = display.getGraphTitle();
		this.totalMaxDepth = maxDepth;
		this.maxLabelLength = 10;
		this.direction = direction;
		this.addresses = addresses;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		DataReferenceGraph graph = new DataReferenceGraph(program, totalMaxDepth);

		monitor.setMessage("Generating Graph...");
		monitor.setIndeterminate(true);

		try {
			for (CodeUnit unit : program.getListing().getCodeUnits(addresses, true)) {
				monitor.checkCanceled();
				AttributedVertex centerVertex =
					graph.graphFrom(unit.getAddress(), direction, monitor);
				/* TODO
				 * Want to make initial vertex easy to find, is this the best way?
				 */
				centerVertex.setAttribute("Color", "Orange");
			}
		}
		catch (CancelledException e) {
			monitor.setMessage("Cancelling");
			graphTitle = graphTitle + " (partial)";
		}

		try {
			if (display == null) {
				display = graphProvider.getGraphDisplay(reuseGraph, monitor);
				display.defineEdgeAttribute(DataReferenceGraph.REF_SOURCE_ATTRIBUTE);
				display.defineEdgeAttribute(DataReferenceGraph.REF_TYPE_ATTRIBUTE);
				display.defineEdgeAttribute(DataReferenceGraph.REF_SYMBOL_ATTRIBUTE);
				display.defineVertexAttribute(DataReferenceGraph.DATA_ATTRIBUTE);
				display.setVertexLabelAttribute(DataReferenceGraph.LABEL_ATTRIBUTE,
					GraphDisplay.ALIGN_LEFT, 12, true, maxLabelLength);

				DataReferenceGraphDisplayListener listener =
					new DataReferenceGraphDisplayListener(tool, display, program, totalMaxDepth);
				display.setGraphDisplayListener(listener);
			}

			display.setGraph(graph, graphTitle, appendGraph, monitor);

			if (location != null) {
				// initialize the graph location, but don't have the graph send an event
				AttributedVertex vertex = graph.getVertex(graph.makeName(location.getAddress()));
				display.setFocusedVertex(vertex, EventTrigger.INTERNAL_ONLY);
			}
		}
		catch (GraphException e) {
			if (!monitor.isCancelled()) {
				Msg.showError(this, null, "Reference Graph Error",
					"Unexpected error while graphing: " + e.getMessage(), e);
			}
		}
	}
}
