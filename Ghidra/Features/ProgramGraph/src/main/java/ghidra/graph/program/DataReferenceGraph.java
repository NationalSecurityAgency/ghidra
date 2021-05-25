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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/*
 * A graph meant to hold data reference information
 * <p>
 * Recursively adds references from a specified address to a specified number
 * of hops. Displays the reference type and source as attributes. Supports graph
 * extension in place.
 */
public class DataReferenceGraph extends AttributedGraph {
	public static final String REF_SOURCE_ATTRIBUTE = "Source";
	// TODO: ref/flow type attribute should be consistent with other program graphs
	//       so that they can be mixed (waiting for standardization)
	public static final String REF_TYPE_ATTRIBUTE = "Type";
	public static final String REF_SYMBOL_ATTRIBUTE = "Symbol";
	public static final String DATA_ATTRIBUTE = "DataType";
	public static final String ADDRESS_ATTRIBUTE = "Address";
	public static final String LABEL_ATTRIBUTE = "Label";

	public enum Directions {
		TO_ONLY, FROM_ONLY, BOTH_WAYS
	}

	private Program program;
	private int depthPerStep;

	/*
	 * Constructor
	 *
	 * @param program the Program to pull references from
	 * @param depth the number of hops to graph per call (0 for recursion until no more hops)
	 */
	public DataReferenceGraph(Program program, int depth) {
		this.program = program;
		this.depthPerStep = depth;
	}

	/*
	 * Constructs the name of the Vertex for the specified address. All addresses in the same CodeUnit
	 * will use the same name/Vertex. If a symbol is available it will use that, otherwise the
	 * string of the address
	 *
	 * @param address address to create the name for
	 * @return String to be used as a VertexId
	 */
	public String makeName(Address address) {
		CodeUnit unit = program.getListing().getCodeUnitContaining(address);
		if (unit == null) {
			return address.toString();
		}
		Address unitAddress = unit.getAddress();

		String name;
		if (program.getSymbolTable().getPrimarySymbol(unitAddress) != null) {
			name = program.getSymbolTable().getPrimarySymbol(unitAddress).getName(true);
		}
		else {
			name = unitAddress.toString();
		}

		return name;
	}

	/*
	 * Graphs the references starting at a specified address. If the specified address
	 * doesn't lead to any references the graph will contain only that address.
	 *
	 * @param baseAddress Address to start graphing from
	 * @param direction controls whether to, from, or both references are followed
	 * @param monitor monitor for cancellation
	 */
	public AttributedVertex graphFrom(Address baseAddress, Directions direction,
			TaskMonitor monitor) throws CancelledException {
		if (baseAddress == null) {
			return null;
		}
		AttributedVertex baseVertex = new AttributedVertex(makeName(baseAddress));
		baseVertex.setAttribute(ADDRESS_ATTRIBUTE, baseAddress.toString());
		setupVertex(baseVertex);
		addVertex(baseVertex);
		recurseGraph(baseAddress, depthPerStep, direction, monitor);
		return baseVertex;
	}

	private void setupEdge(AttributedEdge edge, Reference ref) {
		edge.setAttribute(REF_SOURCE_ATTRIBUTE, ref.getSource().getDisplayString());
		edge.setAttribute(REF_TYPE_ATTRIBUTE, ref.getReferenceType().toString());
		if (ref.getSymbolID() != -1) {
			edge.setAttribute(REF_SYMBOL_ATTRIBUTE,
				program.getSymbolTable().getSymbol(ref.getSymbolID()).getName());
		}
	}

	private void setupVertex(AttributedVertex vertex) {
		Address address =
			program.getAddressFactory().getAddress(vertex.getAttribute(ADDRESS_ATTRIBUTE));
		if (address == null) {
			return;
		}
		CodeUnit unit = program.getListing().getCodeUnitContaining(address);
		if (unit instanceof Data) {
			vertex.setAttribute(DATA_ATTRIBUTE, ((Data) unit).getBaseDataType().getName());
		}
		else if (unit instanceof Instruction) {
			vertex.setAttribute("Icon", "TriangleDown");
		}
	}

	/*
	 * recursion function, maxDepth of zero indicates go to end
	 */
	private void recurseGraph(Address startAddress, int maxDepth, Directions direction,
			TaskMonitor monitor) throws CancelledException {
		AttributedVertex startVertex = getVertex(makeName(startAddress));

		if (direction != Directions.FROM_ONLY) {
			for (Reference ref : program.getListing()
					.getCodeUnitContaining(startAddress)
					.getReferenceIteratorTo()) {
				if (!ref.getReferenceType().isFlow()) {
					Address nextAddress = processReference(Directions.TO_ONLY, startVertex, ref);
					monitor.checkCanceled();
					if (nextAddress != null) {
						/*
						 * maxDepth > 1 -> subtract 1 to count this level, and keep going
						 * maxDepth = 0 -> no limit, always keep going
						 * maxDepth = 1 -> This is the last one, stop recursion
						 */
						if (maxDepth > 1) {
							recurseGraph(nextAddress, maxDepth - 1, direction, monitor);
						}
						else if (maxDepth == 0) {
							recurseGraph(nextAddress, 0, direction, monitor);
						}
					}
				}
			}
		}

		if (direction != Directions.TO_ONLY) {
			for (Reference ref : program.getListing()
					.getCodeUnitContaining(startAddress)
					.getReferencesFrom()) {
				if (!ref.getReferenceType().isFlow()) {
					Address nextAddress = processReference(Directions.FROM_ONLY, startVertex, ref);
					monitor.checkCanceled();
					if (nextAddress != null) {
						/*
						 * maxDepth > 1 -> subtract 1 to count this level, and keep going
						 * maxDepth = 0 -> no limit, always keep going
						 * maxDepth = 1 -> This is the last one, stop recursion
						 */
						if (maxDepth > 1) {
							recurseGraph(nextAddress, maxDepth - 1, direction, monitor);
						}
						else if (maxDepth == 0) {
							recurseGraph(nextAddress, 0, direction, monitor);
						}
					}
				}

			}
		}
	}

	private Address processReference(Directions direction, AttributedVertex startVertex,
			Reference ref) {
		Address targetAddress;
		if (direction == Directions.TO_ONLY) {
			targetAddress = ref.getFromAddress();
		}
		else { //should be FROM_ONLY
			targetAddress = ref.getToAddress();
		}
		AttributedVertex newVertex = new AttributedVertex(makeName(targetAddress));
		newVertex.setAttribute(ADDRESS_ATTRIBUTE, targetAddress.toString());
		setupVertex(newVertex);
		AttributedEdge edge;
		if (direction == Directions.TO_ONLY) {
			edge = addEdge(newVertex, startVertex);
		}
		else { //should be FROM_ONLY
			edge = addEdge(startVertex, newVertex);
		}
		/*
		 * if we've seen this before don't do it again
		 */
		if (edge.hasAttribute("Weight")) {
			return null;
		}
		setupEdge(edge, ref);
		return targetAddress;
	}
}
