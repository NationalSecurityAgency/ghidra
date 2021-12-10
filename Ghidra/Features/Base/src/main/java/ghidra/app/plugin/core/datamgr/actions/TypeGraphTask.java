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
package ghidra.app.plugin.core.datamgr.actions;

import java.awt.Color;

import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.data.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/*
 * Task to recursively graph and display a data type
 *
 * Nodes are generated for pointers and embedded structures
 */
public class TypeGraphTask extends Task {

	private DataType type;
	private String graphTitle;
	private GraphDisplayProvider graphService;

	public static final String COMPOSITE = "Composite";
	public static final String REFERENCE = "Reference";

	/*
	 * Constructor
	 *
	 * @param type the type to graph
	 * @param graphService the GraphService that will display the graph
	 */
	public TypeGraphTask(DataType type, GraphDisplayProvider graphService) {
		super("Graph Data Type", true, false, true);
		this.type = type;
		if (this.type instanceof TypeDef) {
			this.type = ((TypeDef) this.type).getBaseDataType();
		}
		this.graphTitle = "Graph of Type: " + type.getName();
		this.graphService = graphService;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		GraphType graphType = new GraphTypeBuilder("Data Graph")
				.edgeType(REFERENCE)
				.edgeType(COMPOSITE)
				.build();

		GraphDisplayOptions options = new GraphDisplayOptionsBuilder(graphType)
				.defaultVertexColor(Color.BLUE)
				.edge(COMPOSITE, Color.MAGENTA)
				.edge(REFERENCE, Color.BLUE)
				.build();

		AttributedGraph graph = new AttributedGraph(graphTitle, graphType);
		try {
			if (type instanceof Pointer) {
				recursePointer((Pointer) type, graph, null, monitor);
			}
			if (type instanceof Composite) {
				recurseComposite((Composite) type, graph, null, null, monitor);
			}
		}
		catch (CancelledException e) {
			monitor.setMessage("Cancelling...");
			graphTitle = graphTitle + " (partial)";
		}

		GraphDisplay display;
		try {
			display = graphService.getGraphDisplay(false, monitor);
			display.setGraph(graph, options, graphTitle, false, monitor);
		}
		catch (GraphException e) {
			Msg.showError(this, null, "Data Type Graph Error",
				"Unexpected error while graphing: " + e.getMessage(), e);
		}
	}

	private void recurseComposite(Composite struct, AttributedGraph graph,
			AttributedVertex lastVertex, String edgeType, TaskMonitor monitor)
			throws CancelledException {
		AttributedVertex newVertex = new AttributedVertex(struct.getName());
		newVertex.setDescription(ToolTipUtils.getToolTipText(struct));

		if (lastVertex == null) {
			graph.addVertex(newVertex);
		}
		else {
			AttributedEdge edge = graph.addEdge(lastVertex, newVertex);
			edge.setEdgeType(edgeType);
			if (edge.hasAttribute(AttributedGraph.WEIGHT)) {
				//did this already, don't cycle
				return;
			}
		}

		for (DataTypeComponent inner : struct.getComponents()) {
			monitor.checkCanceled();
			DataType dt = inner.getDataType();
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}

			if (dt instanceof Pointer) {
				recursePointer((Pointer) dt, graph, newVertex, monitor);
			}
			else if (dt instanceof Composite) {
				recurseComposite((Composite) dt, graph, newVertex, COMPOSITE, monitor);
			}
		}
	}

	private void recursePointer(Pointer pointer, AttributedGraph graph, AttributedVertex lastVertex,
			TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		DataType ptrType = pointer.getDataType();
		if (ptrType == null) {
			return;
		}
		if (ptrType instanceof TypeDef) {
			ptrType = ((TypeDef) ptrType).getBaseDataType();
		}

		if (ptrType instanceof Pointer) {
			recursePointer((Pointer) ptrType, graph, lastVertex, monitor);
		}
		else if (ptrType instanceof Composite) {
			recurseComposite((Composite) ptrType, graph, lastVertex, REFERENCE, monitor);
		}
	}

}
