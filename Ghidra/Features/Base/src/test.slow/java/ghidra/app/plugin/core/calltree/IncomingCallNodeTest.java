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
package ghidra.app.plugin.core.calltree;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;

import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGenericTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

public class IncomingCallNodeTest extends AbstractGenericTest {

	private ToyProgramBuilder builder;
	private Program program;
	private IncomingCallNode node1;

	private String firstCalledFunctionAddress = "0x0100";
	private String firstCalledFromAddress = "0x1100";

	@Before
	public void setUp() throws Exception {
		builder = new ToyProgramBuilder("Call Node Test", true);
		builder.createMemory(".text", "0x0", 0x3000);

		builder.createFunction(firstCalledFunctionAddress);

		program = builder.getProgram();

		setUpCallNode(false);

		createThunkFunctionCallGraph();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	private void setUpCallNode(boolean hideThunks) {

		FunctionManager fm = program.getFunctionManager();
		Function firstCalledFunction = fm.getFunctionAt(builder.addr(firstCalledFunctionAddress)); // 0x0100
		Address calledFromAddress = builder.addr(firstCalledFromAddress); // 0x0010
		CallTreeOptions callTreeOptions = new CallTreeOptions();
		callTreeOptions = callTreeOptions.withRecurseDepth(5);
		callTreeOptions = callTreeOptions.withFilterThunks(hideThunks);
		node1 =
			new IncomingCallNode(program, firstCalledFunction, calledFromAddress, true,
				callTreeOptions);

	}

	@Test
	public void testGenerateChildren_CalledFunctionIsThunk_ShowThunks() throws Exception {

		/*
		
			node1 @ 0100
		
				node2 (Function_1100)
				
					node3 (Thunk_Function_1050)
				
						node4
						Call: 1200 -> 1050
		 */

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		IncomingCallNode node2 = (IncomingCallNode) children.get(0);
		Address fromAddress = builder.addr("0x1100");
		assertEquals("Function_1100", node2.getName());
		assertEquals(fromAddress, node2.getSourceAddress());

		children = node2.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		IncomingCallNode node3 = (IncomingCallNode) children.get(0);
		assertEquals("Thunk_Function_1050", node3.getName());
		fromAddress = builder.addr("0x1050");

		assertEquals(fromAddress, node3.getSourceAddress());

		children = node3.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size()); // node4; Call: 1200 -> 1050
		IncomingCallNode node4 = (IncomingCallNode) children.get(0);
		fromAddress = addr("0x1200");
		assertEquals("Function_1200", node4.getName());
		assertEquals(fromAddress, node4.getSourceAddress());
	}

	@Test
	public void testGenerateChildren_CalledFunctionIsThunk_HideThunks() throws Exception {

		/*
		
			node1 @ 0100
		
				node2 (Function_1100)
				
					node3 (Thunk_Function_1050) //   <------ This is removed from the tree
				
						node4
						Call: 1200 -> 1050
		 */
		setUpCallNode(true);

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		IncomingCallNode node2 = (IncomingCallNode) children.get(0);
		Address fromAddress = builder.addr("0x1100");
		assertEquals("Function_1100", node2.getName());
		assertEquals(fromAddress, node2.getSourceAddress());

		children = node2.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		IncomingCallNode node3 = (IncomingCallNode) children.get(0);
		assertEquals("Function_1200", node3.getName());
		fromAddress = builder.addr("0x1200");
	}

	private void createThunkFunctionCallGraph() throws Exception {

		/*
		 	
			node1 @ 0100
		
				node2 (Function_1100)
				
					node3 (Thunk_Function_1050)
				
						node4
						Call: 1200 -> 1050
		 */

		String thunkedAddress = "0x1100";
		Function thunkedFunction =
			builder.createEmptyFunction("Function_1100", thunkedAddress, 10, DataType.DEFAULT);
		builder.createMemoryCallReference("0x1100", "0x0100"); // call the root node, node1

		String thunkAddress = "0x1050";
		Function thunkFunction =
			builder.createEmptyFunction("Thunk_Function_1050", thunkAddress, 10, DataType.DEFAULT);
		builder.tx(() -> {
			thunkFunction.setThunkedFunction(thunkedFunction);
		});

		// call from thunk to thunked, node3 -> node2
		builder.createMemoryCallReference(thunkAddress, thunkedAddress);

		// call from somewhere to thunked function, node3
		builder.createEmptyFunction("Function_1200", "0x1200", 10, DataType.DEFAULT);
		builder.createMemoryCallReference("0x1200", thunkAddress);
	}

	@Test
	public void testGenerateChildren_MultipleReferences_SameSource_SameRemoteFunction()
			throws Exception {

		//
		// This is testing when more than 1 reference exists at an address to the same function.
		// We have code that will ensure that call references are preferred over other reference 
		// types, creating one node for the call reference.
		//

		String toAddress = "0x1000";
		Function calledFunction =
			builder.createEmptyFunction("Function_1000", toAddress, 1, new VoidDataType());
		builder.addBytesFallthrough(firstCalledFunctionAddress);
		builder.disassemble(firstCalledFunctionAddress, 2);

		// create non-call read reference
		builder.createMemoryReference(firstCalledFunctionAddress, toAddress, RefType.READ,
			SourceType.USER_DEFINED);

		// create call reference at a different op index so both references can co-exist
		builder.tx(() -> {
			ReferenceManager refManager = program.getReferenceManager();
			Reference ref =
				refManager.addMemoryReference(addr(firstCalledFunctionAddress), addr(toAddress),
					RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 1);
			return ref;
		});

		IncomingCallNode calledNode = new IncomingCallNode(program, calledFunction, addr(toAddress),
			true, new CallTreeOptions());

		List<GTreeNode> children = calledNode.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		IncomingCallNode outgoingNode = (IncomingCallNode) children.get(0);
		assertTrue(outgoingNode.isCallReference());
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private Address addr(String addrString) {
		return builder.addr(addrString);
	}

}
