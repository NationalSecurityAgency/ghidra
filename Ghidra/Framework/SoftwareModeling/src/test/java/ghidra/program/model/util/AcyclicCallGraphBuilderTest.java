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

import static ghidra.util.task.TaskMonitorAdapter.DUMMY_MONITOR;

import java.util.*;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.graph.AbstractDependencyGraph;

public class AcyclicCallGraphBuilderTest extends AbstractGenericTest {

	// multiple used space functions out, i.e function 1 is at 0x100, function 2 is at 0x200
	private static final int HEX_100 = 256;

	private AddressSpace space = new GenericAddressSpace("Test", 32, AddressSpace.TYPE_RAM, 0);

	Set<Function> functions = new HashSet<Function>();
	ReferenceState refState = new ReferenceState();
	Map<Address, Function> functionMap = new HashMap<Address, Function>();
	Program program = createProgram();

	public AcyclicCallGraphBuilderTest() {
		super();
	}

	private void node(int functionID, int... destFunctionIDs) {
		Address address = functionAddress(functionID);
		createFunction(address);
		for (int id : destFunctionIDs) {
			Address toAddr = functionAddress(id);
			refState.createReference(address, toAddr);
			createFunction(toAddr);
		}
	}

	private void thunkNode(int functionID, int destFunctionID, boolean hasRef) {
		Address address = functionAddress(functionID);
		Address toAddr = functionAddress(destFunctionID);
		createThunkFunction(address, toAddr);
		if(hasRef) { //A thunk might not have a reference to the thunked.
			refState.createReference(address, toAddr);
		}
	}

	private void createFunction(Address address) {
		if (!functionMap.containsKey(address)) {
			Function function = createFunction(address.toString(), address);
			functions.add(function);
			functionMap.put(address, function);
		}
	}

	private void createThunkFunction(Address address, Address toAddr) {
		Function function;
		Function thunkedFunction;
		if (functionMap.containsKey(address)) {
			function = functionMap.get(address);
		}
		else {
			function = createFunction(address.toString(), address);
			functions.add(function);
			functionMap.put(address, function);
		}
		if (functionMap.containsKey(toAddr)) {
			thunkedFunction = functionMap.get(toAddr);
		}
		else {
			thunkedFunction = createFunction(toAddr.toString(), toAddr);
			functions.add(thunkedFunction);
			functionMap.put(toAddr, thunkedFunction);
		}
		function.setThunkedFunction(thunkedFunction);
	}

@Test
    public void testDiamondGraph() throws Exception {
		node(1, 2);
		node(1, 3);
		node(2, 4);
		node(3, 4);

		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, functions, false);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(DUMMY_MONITOR);

		Assert.assertEquals(4, graph.size());

		assertDependents(graph, 4, 2, 3);
		assertDependents(graph, 2, 1);
		assertDependents(graph, 3, 1);
		assertDependents(graph, 1);
	}

@Test
    public void test3SidedDiamondGraph() throws Exception {
		node(1,2);
		node(1,3);
		node(2,3);
		
		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program,functions,false);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(DUMMY_MONITOR);
		
		Assert.assertEquals(3, graph.size());
		
		assertDependents(graph, 3, 1, 2);
		assertDependents(graph, 2, 1);
		assertDependents(graph, 1);
	}
	
@Test
    public void testSimpleCycle() throws Exception {
		node(1, 2);
		node(2, 3);
		node(3, 1);

		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, functions, false);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(DUMMY_MONITOR);

		Assert.assertEquals(3, graph.size());

		assertDependents(graph, 3, 2);
		assertDependents(graph, 2, 1);
		assertDependents(graph, 1);
	}

@Test
    public void testNodeWithSelfCycle() throws Exception {
		node(1, 2);
		node(2, 3);
		node(3, 1);
		node(2, 2);

		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, functions, false);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(DUMMY_MONITOR);

		Assert.assertEquals(3, graph.size());

		assertDependents(graph, 3, 2);
		assertDependents(graph, 2, 1);
		assertDependents(graph, 1);
	}

@Test
    public void testWhereFirstNodeIsNotRoot() throws Exception {
		node(1, 3);
		node(2, 3);
		node(3, 1);

		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, functions, false);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(DUMMY_MONITOR);

		Assert.assertEquals(3, graph.size());

		assertDependents(graph, 1, 3);
		assertDependents(graph, 3, 2);
		assertDependents(graph, 2);
	}

@Test
    public void testSimpleThunks() throws Exception {
		node(1, 2);
		node(1, 4);
		node(1, 6);
		node(1, 9);
		node(1, 12);
		node(1, 13);
		thunkNode(2, 3, true);
		thunkNode(4, 5, false);
		thunkNode(6, 7, true);
		thunkNode(7, 8, true);
		thunkNode(9, 10, false);
		thunkNode(10, 11, false);
		thunkNode(12, 14, false);
		thunkNode(13, 14, false);
		thunkNode(15, 16, true);
		thunkNode(17, 18, false);

		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, functions, false);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(DUMMY_MONITOR);

		Assert.assertEquals(18, graph.size());

		assertDependents(graph, 2, 1);
		assertDependents(graph, 4, 1);
		assertDependents(graph, 6, 1);
		assertDependents(graph, 9, 1);
		assertDependents(graph, 12, 1);
		assertDependents(graph, 13, 1);
		assertDependents(graph, 3, 2);
		assertDependents(graph, 5, 4);
		assertDependents(graph, 7, 6);
		assertDependents(graph, 8, 7);
		assertDependents(graph, 10, 9);
		assertDependents(graph, 11, 10);
		assertDependents(graph, 14, 12, 13);
		assertDependents(graph, 1);
		assertDependents(graph, 16, 15);
		assertDependents(graph, 15);
		assertDependents(graph, 18, 17);
		assertDependents(graph, 17);
	}

@Test
    public void testKilledThunks() throws Exception {
		node(1, 2);
		node(1, 4);
		node(1, 6);
		node(1, 9);
		node(1, 12);
		node(1, 13);
		thunkNode(2, 3, true);
		thunkNode(4, 5, false);
		thunkNode(6, 7, true);
		thunkNode(7, 8, true);
		thunkNode(9, 10, false);
		thunkNode(10, 11, false);
		thunkNode(12, 14, false);
		thunkNode(13, 14, false);
		thunkNode(15, 16, true);
		thunkNode(17, 18, false);

		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, functions, true);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(DUMMY_MONITOR);

		Assert.assertEquals(8, graph.size());

		assertDependents(graph, 3, 1);
		assertDependents(graph, 5, 1);
		assertDependents(graph, 8, 1);
		assertDependents(graph, 11, 1);
		assertDependents(graph, 14, 1);
		assertDependents(graph, 1);
		assertDependents(graph, 15);
		assertDependents(graph, 17);
	}

	@Test
	public void testRecurseThruThunk() throws Exception {
		node(1, 2);
		node(2, 3);		// Recursion between 2 and 3
		node(3, 2);
		node(3, 4);
		node(1, 5);

		thunkNode(5, 3, true);	// Thunk node hits recursion from different point
		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, functions, true);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(DUMMY_MONITOR);

		Assert.assertEquals(4, graph.size());
		assertDependents(graph, 2, 1);
		assertDependents(graph, 3, 1, 2);

		Assert.assertFalse(graph.hasCycles());
	}

	private void assertDependents(AbstractDependencyGraph<Address> graph, int fromID, int... toIDs) {
		Set<Address> expectedSet = new HashSet<Address>();
		for (int toAddr : toIDs) {
			expectedSet.add(functionAddress(toAddr));
		}
		Set<Address> dependentSet = graph.getDependentValues(functionAddress(fromID));
		Assert.assertEquals("DependentSet has unexpected values:", expectedSet, dependentSet);
	}

	private FunctionManager createFunctionManager() {
		return new FunctionManagerTestDouble() {
			@Override
			public Function getFunctionAt(Address addr) {
				return functionMap.get(addr);
			}
		};
	}

	private Program createProgram() {
		final FunctionManager funMgr = createFunctionManager();
		return new ProgramTestDouble() {
			@Override
			public ReferenceManager getReferenceManager() {
				return refState;
			}

			@Override
			public FunctionManager getFunctionManager() {
				return funMgr;
			}
		};
	}

	private Function createFunction(String name, final Address address) {
		return new FunctionTestDouble(name) {
			private Function thunkedFunction = null;

			@Override
			public Address getEntryPoint() {
				return address;
			}

			@Override
			public AddressSetView getBody() {
				return new AddressSet(address, address.add(0x10));
			}
			
			@Override
			public void setThunkedFunction(Function thunkedFunction) {
				this.thunkedFunction = thunkedFunction;
			}
			
			@Override
			public Function getThunkedFunction(boolean recursive) {
				if(!recursive || thunkedFunction == null ) {
					return thunkedFunction;
				}
				Function thunked = thunkedFunction;
				while(thunked.isThunk()) {
					thunked = thunked.getThunkedFunction(recursive);
				}
				return thunked;
			}
			
			@Override
			public boolean isThunk() {
				return(thunkedFunction != null);
			}
		};
	}

	private Address addr(int offset) {
		return space.getAddress(offset);
	}

	private Address functionAddress(int functionID) {
		return addr(functionID * HEX_100);
	}
}
