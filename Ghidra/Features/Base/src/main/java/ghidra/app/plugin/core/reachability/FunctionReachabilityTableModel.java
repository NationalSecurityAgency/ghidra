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
package ghidra.app.plugin.core.reachability;

import java.util.*;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.services.BlockModelService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.graph.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskMonitor;

public class FunctionReachabilityTableModel
		extends GhidraProgramTableModel<FunctionReachabilityResult> {

	private static final int FROM_FUNCTION_COLUMN = 0;
	private static final int TO_FUNCTION_COLUMN = 1;

	private Function fromFunction;
	private Function toFunction;

	FunctionReachabilityTableModel(ServiceProvider sp, Program p) {
		super("Function Reachability Model", sp, p, null, true);
		setProgram(p);
	}

	@Override
	protected TableColumnDescriptor<FunctionReachabilityResult> createTableColumnDescriptor() {
		TableColumnDescriptor<FunctionReachabilityResult> descriptor =
			new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new FromFunctionTableColumn());
		descriptor.addVisibleColumn(new ToFunctionTableColumn());
		descriptor.addVisibleColumn(new PathLengthTableColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<FunctionReachabilityResult> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (fromFunction == null || toFunction == null) {
			return;
		}

		monitor.setIndeterminate(true);

		monitor.setMessage("Creating callgraph...");

		Map<Address, FRVertex> instanceMap = new HashMap<>();
		FRVertex v1 = new FRVertex(fromFunction.getEntryPoint());
		FRVertex v2 = new FRVertex(toFunction.getEntryPoint());
		instanceMap.put(fromFunction.getEntryPoint(), v1);
		instanceMap.put(toFunction.getEntryPoint(), v2);

		GDirectedGraph<FRVertex, FREdge> graph = createCallGraph(instanceMap, monitor);

		// debug
		// GraphAlgorithms.printGraph(graph);

		Accumulator<List<FRVertex>> pathAccumulator = new PassThroughAccumulator(accumulator);

		if (v1.equals(v2)) {
			return;
		}

		monitor.setMessage("Finding paths...");
		GraphAlgorithms.findPaths(graph, v1, v2, pathAccumulator, monitor);
	}

	protected GDirectedGraph<FRVertex, FREdge> createCallGraph(Map<Address, FRVertex> instanceMap,
			TaskMonitor monitor) throws CancelledException {

		/*
		 			 TODO
					 TODO
					 TODO  This code is not picking-up memory references.  The ReferencesUtils
					       should be used to generate calling information instead
					 TODO
					 TODO
		 
		 */

		GDirectedGraph<FRVertex, FREdge> graph = GraphFactory.createDirectedGraph();

		CodeBlockIterator codeBlocks = getCallGraphBlocks(monitor);
		while (codeBlocks.hasNext()) {
			monitor.checkCanceled();

			CodeBlock block = codeBlocks.next();
			monitor.setMessage("Creating callgraph - block " + block.getMinAddress());

			FRVertex fromVertex = instanceMap.get(block.getFirstStartAddress());
			if (fromVertex == null) {
				fromVertex = new FRVertex(block.getFirstStartAddress());
				instanceMap.put(block.getFirstStartAddress(), fromVertex);
				graph.addVertex(fromVertex);
			}

			// destinations section
			addEdgesForDestinations(graph, fromVertex, block, instanceMap, monitor);
		}
		return graph;
	}

	private CodeBlockIterator getCallGraphBlocks(TaskMonitor monitor) throws CancelledException {
		BlockModelService blockModelService = serviceProvider.getService(BlockModelService.class);

		CodeBlockModel model;
		try {
			model = blockModelService.getNewModelByName(
				BlockModelService.ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME);
		}
		catch (NotFoundException e) {
			Msg.error(this, "Code block model not found: " +
				BlockModelService.ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME);
			model = blockModelService.getActiveSubroutineModel();
		}

		return model.getCodeBlocks(monitor);
	}

	private void addEdgesForDestinations(GDirectedGraph<FRVertex, FREdge> graph,
			FRVertex fromVertex, CodeBlock sourceBlock, Map<Address, FRVertex> vertexMap,
			TaskMonitor monitor) throws CancelledException {

		CodeBlockReferenceIterator iterator = sourceBlock.getDestinations(monitor);
		while (iterator.hasNext()) {
			monitor.checkCanceled();

			CodeBlockReference destination = iterator.next();
			CodeBlock targetBlock = getDestinationBlock(destination, monitor);
			if (targetBlock == null) {
				continue; // no block found
			}

			FRVertex targetVertex = vertexMap.get(targetBlock.getFirstStartAddress());
			if (targetVertex == null) {
				targetVertex = new FRVertex(targetBlock.getFirstStartAddress());
				vertexMap.put(targetBlock.getFirstStartAddress(), targetVertex);
			}

			targetVertex.addReference(fromVertex, destination);

			graph.addVertex(targetVertex);
			graph.addEdge(new FREdge(fromVertex, targetVertex));
		}
	}

	private CodeBlock getDestinationBlock(CodeBlockReference destination, TaskMonitor monitor)
			throws CancelledException {

		Address targetAddress = destination.getDestinationAddress();
		BlockModelService blockModelService = serviceProvider.getService(BlockModelService.class);
		CodeBlockModel codeBlockModel = blockModelService.getActiveSubroutineModel();
		CodeBlock targetBlock = codeBlockModel.getFirstCodeBlockContaining(targetAddress, monitor);
		if (targetBlock == null) {
			return null; // no code found for call; external?
		}

		return targetBlock;
	}

	void setFunctions(Function from, Function to) {
		this.fromFunction = from;
		this.toFunction = to;
		reload();
	}

	@Override
	public Program getDataSource() {
		return program;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		FunctionReachabilityResult result = getRowObject(row);
		if (column == FROM_FUNCTION_COLUMN) {
			Function function = result.getFromFunction();
			Address address = function.getEntryPoint();
			return new ProgramLocation(getProgram(), address);
		}
		else if (column == TO_FUNCTION_COLUMN) {
			Function function = result.getToFunction();
			Address address = function.getEntryPoint();
			return new ProgramLocation(getProgram(), address);
		}
		return null;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		// TODO I don't think this makes sense for a table with multiple address columns 
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class PassThroughAccumulator implements Accumulator<List<FRVertex>> {

		private Accumulator<FunctionReachabilityResult> accumulator;

		PassThroughAccumulator(Accumulator<FunctionReachabilityResult> accumulator) {
			this.accumulator = accumulator;
		}

		@Override
		public Iterator<List<FRVertex>> iterator() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void add(List<FRVertex> t) {
			accumulator.add(new FunctionReachabilityResult(fromFunction, toFunction, t));
		}

		@Override
		public void addAll(Collection<List<FRVertex>> collection) {
			for (List<FRVertex> list : collection) {
				accumulator.add(new FunctionReachabilityResult(fromFunction, toFunction, list));
			}
		}

		@Override
		public boolean contains(List<FRVertex> t) {
			throw new UnsupportedOperationException();
		}

		@Override
		public Collection<List<FRVertex>> get() {
			throw new UnsupportedOperationException();
		}

		@Override
		public int size() {
			return accumulator.size();
		}

	}

	private class FromFunctionTableColumn
			extends AbstractDynamicTableColumn<FunctionReachabilityResult, String, Program> {

		@Override
		public String getColumnName() {
			return "From";
		}

		@Override
		public String getValue(FunctionReachabilityResult rowObject, Settings settings,
				Program data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getFromFunction().toString();
		}
	}

	private class ToFunctionTableColumn
			extends AbstractDynamicTableColumn<FunctionReachabilityResult, String, Program> {

		@Override
		public String getColumnName() {
			return "To";
		}

		@Override
		public String getValue(FunctionReachabilityResult rowObject, Settings settings,
				Program data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getToFunction().toString();
		}
	}

	private class PathLengthTableColumn
			extends AbstractDynamicTableColumn<FunctionReachabilityResult, Integer, Program> {
		@Override
		public String getColumnName() {
			return "Length";
		}

		@Override
		public String getColumnDescription() {
			return "The length of this path";
		}

		@Override
		public Integer getValue(FunctionReachabilityResult rowObject, Settings settings,
				Program data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getPathLength();
		}
	}
}
