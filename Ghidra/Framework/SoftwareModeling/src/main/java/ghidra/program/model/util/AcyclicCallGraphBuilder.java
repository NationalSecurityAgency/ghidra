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
package ghidra.program.model.util;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.graph.DependencyGraph;
import ghidra.util.task.TaskMonitor;

/**
 * Class to build an DependencyGraph base on a acyclic function call graph.  This is useful when
 * you want to process functions "bottom up".
 */
public class AcyclicCallGraphBuilder {
	private Program program;
	private Set<Address> functionSet;
	private boolean killThunks;

	/**
	 * Creates a DependencyGraph of all functions in a program based on the call graph.
	 * @param program the program to create an acyclic call graph
	 * @param killThunks true if thunked functions should be eliminated from the graph
	 */
	public AcyclicCallGraphBuilder(Program program, boolean killThunks) {
		this(program, program.getMemory(), killThunks);
	}

	/**
	 * Creates a DependencyGraph of all functions in the given addressSet based on the call graph.
	 * Calls to or from functions outside the given address set are ignored.
	 * @param program the program to create an acyclic call graph
	 * @param set the address to restrict the call graph.
	 * @param killThunks true if thunked functions should be eliminated from the graph
	 */
	public AcyclicCallGraphBuilder(Program program, AddressSetView set, boolean killThunks) {
		this.program = program;
		this.functionSet = findFunctions(program, set, killThunks);
		this.killThunks = killThunks;
	}

	/**
	 * Creates a DependencyGraph of all functions in the given set of functions based on the call graph.
	 * Calls to or from functions not in the given set are ignored.
	 * @param program the program to create an acyclic call graph
	 * @param functions the set of functions to include in the call graph.
	 * @param killThunks true if thunked functions should be eliminated from the graph
	 */
	public AcyclicCallGraphBuilder(Program program, Collection<Function> functions,
			boolean killThunks) {
		this.program = program;
		functionSet = new HashSet<>();
		for (Function function : functions) {
			if (killThunks) {
				if (function.isThunk()) {
					function = function.getThunkedFunction(true);
				}
			}
			functionSet.add(function.getEntryPoint());
		}
		this.killThunks = killThunks;
	}

	/**
	 * Builds the DependencyGraph for the acyclic call graph represented by this object.
	 * @param monitor the taskMonitor to use for reporting progress or cancelling.
	 * @return the DependencyGraph for the acyclic call graph represented by this object.
	 * @throws CancelledException if the monitor was cancelled.
	 */
	public AbstractDependencyGraph<Address> getDependencyGraph(TaskMonitor monitor)
			throws CancelledException {

		AbstractDependencyGraph<Address> graph = new DependencyGraph<>();
		Deque<Address> startPoints = findStartPoints();
		Set<Address> unprocessed = new TreeSet<>(functionSet); // reliable processing order
		monitor.initialize(unprocessed.size());
		while (!unprocessed.isEmpty()) {
			monitor.checkCanceled();
			Address functionEntry = getNextStartFunction(startPoints, unprocessed);
			processForward(graph, unprocessed, functionEntry, monitor);
		}

		return graph;
	}

	private Address getNextStartFunction(Deque<Address> startPoints, Set<Address> unProcessedSet) {
		while (!startPoints.isEmpty()) {
			Address address = startPoints.pop();
			if (unProcessedSet.contains(address)) {
				return address;
			}
		}
		return unProcessedSet.iterator().next();
	}

	private Deque<Address> findStartPoints() {
		Deque<Address> startPoints = new LinkedList<>();

		// populate startPoints with functions that have no callers or are an entry point
		for (Address address : functionSet) {
			if (isStartFunction(address)) {
				startPoints.add(address);
			}
		}
		return startPoints;
	}

	private void initializeNode(StackNode node) {
		FunctionManager fmanage = program.getFunctionManager();
		Function function = fmanage.getFunctionAt(node.address);
		if (function.isThunk()) {
			Function thunkedfunc = function.getThunkedFunction(false);
			node.children = new Address[1];
			node.children[0] = thunkedfunc.getEntryPoint();
			return;
		}
		ArrayList<Address> children = new ArrayList<>();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator referenceSourceIterator =
			referenceManager.getReferenceSourceIterator(function.getBody(), true);

		while (referenceSourceIterator.hasNext()) {
			Address fromAddr = referenceSourceIterator.next();
			for (Reference ref : referenceManager.getFlowReferencesFrom(fromAddr)) {
				Address toAddr = ref.getToAddress();
				if (ref.getReferenceType().isCall()) {
					Function childfunc = fmanage.getFunctionAt(toAddr);
					if (childfunc != null && killThunks) {
						if (childfunc.isThunk()) {
							childfunc = childfunc.getThunkedFunction(true);
							toAddr = childfunc.getEntryPoint();
						}
					}
					if (functionSet.contains(toAddr)) {
						children.add(toAddr);
					}
				}
			}
		}
		node.children = new Address[children.size()];
		children.toArray(node.children);
	}

	private void processForward(AbstractDependencyGraph<Address> graph, Set<Address> unprocessed,
			Address startFunction, TaskMonitor monitor) throws CancelledException {
		VisitStack stack = new VisitStack(startFunction);
		StackNode curnode = stack.peek();
		initializeNode(curnode);
		graph.addValue(curnode.address);
		while (!stack.isEmpty()) {
			monitor.checkCanceled();

			curnode = stack.peek();
			if (curnode.nextchild >= curnode.children.length) {		// Node more to children to traverse for this node
				unprocessed.remove(curnode.address);
				monitor.incrementProgress(1);
				stack.pop();
			}
			else {
				Address childAddr = curnode.children[curnode.nextchild++];
				if (!stack.contains(childAddr)) {
					if (unprocessed.contains(childAddr)) {
						stack.push(childAddr);
						StackNode nextnode = stack.peek();
						initializeNode(nextnode);
						childAddr = nextnode.address;
						graph.addValue(nextnode.address);
					}
					graph.addDependency(curnode.address, childAddr);
				}
			}
		}
	}

	private boolean isStartFunction(Address address) {
		ReferenceManager referenceManager = program.getReferenceManager();
		Iterable<Reference> referencesTo = referenceManager.getReferencesTo(address);

		for (Reference reference : referencesTo) {
			if (reference.isEntryPointReference()) {
				return true;
			}
			if (reference.getReferenceType().isCall()) {
				//Assume that any call implies that none of the references will be entry point reference.
				return false;
			}
		}
		return true;
	}

	private static Set<Address> findFunctions(Program program, AddressSetView set,
			boolean killThunks) {
		Set<Address> functionStarts = new HashSet<>();

		FunctionIterator functions = program.getFunctionManager().getFunctions(set, true);
		for (Function function : functions) {
			if (killThunks) {
				if (function.isThunk()) {
					function = function.getThunkedFunction(true);
				}
			}
			functionStarts.add(function.getEntryPoint());
		}

		return functionStarts;
	}

	private static class StackNode {
		public Address address;
		public Address[] children;
		public int nextchild;

		@Override
		public String toString() {
			return address == null ? ""
					: address.toString() +
						(children == null ? " <no children>" : " " + Arrays.toString(children));
		}
	}

	private static class VisitStack {
		private Set<Address> inStack = new HashSet<>();
		private Deque<StackNode> stack = new LinkedList<>();

		public VisitStack(Address functionEntry) {
			push(functionEntry);
		}

		public boolean isEmpty() {
			return stack.isEmpty();
		}

		public StackNode peek() {
			return stack.peek();
		}

		public boolean contains(Address address) {
			return inStack.contains(address);
		}

		public void push(Address address) {
			if (!inStack.add(address)) {
				throw new IllegalStateException(
					"Attempted to visit an address that is already on the stack");
			}
			StackNode newnode = new StackNode();
			newnode.address = address;
			newnode.nextchild = 0;
			stack.push(newnode);
		}

		public void pop() {
			Address address = stack.pop().address;
			inStack.remove(address);
		}

	}
}
