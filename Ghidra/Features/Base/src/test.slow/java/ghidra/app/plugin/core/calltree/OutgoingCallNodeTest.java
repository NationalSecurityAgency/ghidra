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
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;
import utility.function.ExceptionalCallback;

/**
 * This test class is covering the various types of 'calls' a function can make, such as a
 * direct call instruction, or through a user-defined reference.   External calls are also a bit
 * tricky.   This test was created by following the code paths in {@link OutgoingCallNode}
 * and making sure that each path was followed.
 */
public class OutgoingCallNodeTest extends AbstractGenericTest {

	private ToyProgramBuilder builder;
	private Program program;
	private OutgoingCallNode node1;

	private String firstCallSourceAddress = "0x0010";
	private String firstCalledFunctionAddress = "0x0100";

	@Before
	public void setUp() throws Exception {
		builder = new ToyProgramBuilder("Call Node Test", true);
		builder.createMemory(".text", "0x0", 0x3000);

		Function firstCalledFunction = builder.createFunction(firstCalledFunctionAddress);

		program = builder.getProgram();

		Address calledFromAddress = builder.addr(firstCallSourceAddress); // fake
		CallTreeOptions callTreeOptions = new CallTreeOptions();
		callTreeOptions = callTreeOptions.withRecurseDepth(5);
		node1 =
			new OutgoingCallNode(program, firstCalledFunction, calledFromAddress, true,
				callTreeOptions);
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testGenerateChildren_SelfRecursiveCall() throws Exception {

		builder.createMemoryCallReference(firstCalledFunctionAddress, firstCalledFunctionAddress);

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());

	}

	@Test
	public void testGenerateChildren_SelfRecursiveReference() throws Exception {

		builder.createMemoryReadReference(firstCalledFunctionAddress, firstCalledFunctionAddress);

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());

	}

	@Test
	public void testGenerateChildren_CalledFunctionExists() throws Exception {
		String otherAddress = "0x1000";
		builder.createEmptyFunction("Function_1000", otherAddress, 10, DataType.DEFAULT);
		builder.createMemoryCallReference(firstCalledFunctionAddress, otherAddress);

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertEquals("Function_1000", children.get(0).getName());
	}

	@Test
	public void testGenerateChildren_CalledFunctionIsThunk_ShowThunks() throws Exception {

		/*
		
		node1
		0010 -> Function @ 0100
		
			node2
			Call: 0100 -> Thunk_Function_1050 @ 1050
			
				node3
				Call: 1050 -> Function_1100 @ 1100
				
					node4
					Call: 1100 -> 1200
		*/
		createThunkFunctionCallGraph();

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		OutgoingCallNode node2 = (OutgoingCallNode) children.get(0);
		Address fromAddress = builder.addr("0x0100");
		Address toAddress = builder.addr("0x1050"); // thunk address
		assertEquals("Thunk_Function_1050", node2.getName());
		assertEquals(fromAddress, node2.getSourceAddress());
		assertEquals(toAddress, node2.getRemoteFunction().getEntryPoint());

		children = node2.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		OutgoingCallNode node3 = (OutgoingCallNode) children.get(0);
		assertEquals("Function_1100", node3.getName());

		children = node2.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size()); // node4; Call: 1100 -> 1200
	}

	@Test
	public void testGenerateChildren_CalledFunctionIsThunk_HideThunks() throws Exception {

		setUpCallNodeWithThunksHidden();

		/*
		
		node1
		0010 -> Function @ 0100
		
			node2
			Call: 0100 -> Thunk_Function_1050 @ 1050 //  <------ ignored thunk; omitted from tree
			
				node3
				Call: 1050 -> Function_1100 @ 1100
				
					node4
					Call: 1100 -> 1200
		*/
		createThunkFunctionCallGraph();

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());

		// second node from above should be skipped, since it is at thunk
		OutgoingCallNode node3 = (OutgoingCallNode) children.get(0);
		Address fromAddress = addr("0x0100");
		Address toAddress = addr("0x1100"); // thunked address; no thunk		

		// verify the function for the child is not the thunk function; the thunk is ignored
		assertEquals("Function_1100", node3.getName());
		assertEquals(fromAddress, node3.getSourceAddress());
		assertEquals(toAddress, node3.getRemoteFunction().getEntryPoint());

		children = node3.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size()); // Call: 1100 -> 1200
		DeadEndNode node4 = (DeadEndNode) children.get(0);
		fromAddress = addr("0x1100");
		toAddress = addr("0x1200");
		assertEquals(fromAddress, node4.getSourceAddress());
		assertEquals(toAddress, node4.getRemoteAddress());
	}

	@Test
	public void testGenerateChildren_CalledFunctionExists_ExternalCall() throws Exception {
		String otherAddress = "0x1000";

		String externalFunctionName = "External_Function";
		ExternalLocation location =
			builder.createExternalFunction(otherAddress, "ExternalLibrary", externalFunctionName);

		builder.createMemoryCallReference(firstCalledFunctionAddress,
			location.getExternalSpaceAddress().toString());

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertEquals(externalFunctionName, children.get(0).getName());
	}

	@Test
	public void testGenerateChildren_CallReference_ExternalFunction_NoFunctionInMemory()
			throws Exception {

		builder.createMemoryCallReference(firstCalledFunctionAddress, "EXTERNAL:00000001");

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertEquals("EXTERNAL:00000001", children.get(0).getName());
	}

	@Test
	public void testGenerateChildren_CallReference_ToPointer_ToExternalFunction() throws Exception {

		//
		// Function A
		//  -> has memory reference to a pointer
		//     -> this pointer has an external reference to a function
		//

		Reference ref = builder.createMemoryCallReference(firstCalledFunctionAddress, "0x2000");

		Address toAddress = ref.getToAddress();
		builder.applyDataType(toAddress.toString(), new Pointer32DataType());

		String externalFunctionName = "External_Function";
		ExternalLocation location =
			builder.createExternalFunction("0x2020", "ExternalLibrary", externalFunctionName);

		builder.createMemoryReadReference(toAddress.toString(),
			location.getExternalSpaceAddress().toString());

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertEquals(externalFunctionName, children.get(0).getName());
	}

	@Test
	public void testGenerateChildren_CallReference_ToPointer_ToNonExternalFunction()
			throws Exception {

		//
		// Function A
		//  -> has memory reference to a pointer
		//     -> this pointer has an non-external reference to a function
		//

		Reference ref = builder.createMemoryCallReference(firstCalledFunctionAddress, "0x2000");

		Address toAddress = ref.getToAddress();
		builder.applyDataType(toAddress.toString(), new Pointer32DataType());

		String functionAddress = "0x2020";
		builder.createEmptyFunction("Function_2020", functionAddress, 1, new VoidDataType());

		builder.createMemoryReadReference(toAddress.toString(), functionAddress);

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertTrue(children.get(0) instanceof DeadEndNode);
	}

	@Test
	public void testGenerateChildren_CallReference_ToPointer_Offcut() throws Exception {

		//
		// Bad code case; expected reference to pointer, but no data there
		//

		String dataAddress = "0x2000";
		String offcutAddress = "0x2001";
		builder.applyDataType(dataAddress, new Pointer32DataType());
		builder.createMemoryCallReference(firstCalledFunctionAddress, offcutAddress);

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertTrue(children.get(0) instanceof DeadEndNode);
	}

	@Test
	public void testGenerateChildren_WriteReference() throws Exception {

		//
		// Have a reference in the function to a place that is not another function, and the
		// reference is a write reference.  No call node is created.
		//

		builder.createMemoryReference(firstCalledFunctionAddress, "0x1000", RefType.WRITE,
			SourceType.USER_DEFINED);
		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_NullInstruction() throws Exception {

		//
		// Have a reference in the function to a place that is not another function, and the
		// reference is a read reference.
		// Note: since we did not have the builder put an instruction at the 'to' address,
		//       the instruction there is null.
		//

		builder.createMemoryReference(firstCalledFunctionAddress, "0x1000", RefType.READ,
			SourceType.USER_DEFINED);
		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());

	}

	@Test
	public void testGenerateChildren_ReadReference_NotCallInstruction_NoFunctionAtToAddress()
			throws Exception {

		//
		// Read reference to an instruction with a flow type that is not a call.  There is no 
		// function a the destination.
		//

		builder.addBytesFallthrough(firstCalledFunctionAddress);
		builder.disassemble(firstCalledFunctionAddress, 2);

		builder.createMemoryReference(firstCalledFunctionAddress, "0x1000", RefType.READ,
			SourceType.USER_DEFINED);
		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_NotCallInstruction_FunctionAtToAddress()
			throws Exception {

		//
		// Read reference to an instruction with a flow type that is not a call.  There is a 
		// function at the destination.
		//

		String toAddress = "0x1000";
		builder.createEmptyFunction("Function_1000", toAddress, 1, new VoidDataType());
		builder.addBytesFallthrough(firstCalledFunctionAddress);
		builder.disassemble(firstCalledFunctionAddress, 2);

		builder.createMemoryReference(firstCalledFunctionAddress, toAddress, RefType.READ,
			SourceType.USER_DEFINED);
		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
	}

	@Test
	public void testGenerateChildren_ReadReference_CallInstruction_InstructionAtToAddress()
			throws Exception {

		//
		// Read reference from an instruction with a flow type of call to a place that is an
		// instruction (and thus is not a pointer to a function)
		//

		createCallInstruction();

		// instruction at the other side
		builder.addBytesNOP(0x1000, 2);
		builder.disassemble("0x1000", 2);

		builder.createMemoryReference(firstCalledFunctionAddress, "0x1000", RefType.READ,
			SourceType.USER_DEFINED);
		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_CallInstruction_ToData_NoReference()
			throws Exception {

		//
		// Read reference from an instruction with a flow type of call.
		//

		createCallInstruction();

		builder.createMemoryReference(firstCalledFunctionAddress, "0x1000", RefType.READ,
			SourceType.USER_DEFINED);
		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_CallInstruction_ToData_NonExternalReference()
			throws Exception {

		//
		// Read reference from an instruction with a flow type that is a call, to a non-external place
		//

		createCallInstruction();

		builder.createMemoryReference(firstCalledFunctionAddress, "0x1000", RefType.READ,
			SourceType.USER_DEFINED);

		// put a non-external reference on the data at the 'to' address
		builder.createMemoryCallReference("0x1000", "0x1020");

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_CallInstruction_ToData_ExternalReference_NonFunctionSymbol()
			throws Exception {

		//
		// Read reference from an instruction with a flow type that is a call, to a external place
		//

		createCallInstruction();

		builder.createMemoryReference(firstCalledFunctionAddress, "0x1000", RefType.READ,
			SourceType.USER_DEFINED);

		// put a external reference on the data at the 'to' address
		builder.createExternalReference("0x1000", "ExternalLib", "ExternalLabel", 0);

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_CallInstruction_ToData_ExternalReference_FunctionSymbol()
			throws Exception {

		//
		// Read reference from an instruction with a flow type that is a call, to an external
		// function symbol
		//

		createCallInstruction();

		builder.createMemoryReference(firstCalledFunctionAddress, "0x1000", RefType.READ,
			SourceType.USER_DEFINED);

		// put a external reference on the data at the 'to' address that calls the external function
		ExternalLocation location =
			builder.createExternalFunction("0x1020", "ExternalLib", "ExternalFunction_1");
		builder.createMemoryReadReference("0x1000", location.getExternalSpaceAddress().toString());

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertTrue(children.get(0) instanceof DeadEndNode);
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

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		OutgoingCallNode outgoingNode = (OutgoingCallNode) children.get(0);
		assertTrue(outgoingNode.isCallReference());
	}

	@Test
	public void testGenerateChildren_MultipleReferences_SameSource_DifferentRemoteFunction()
			throws Exception {

		//
		// This is testing when more than 1 reference exists at an address to different functions.
		// We have code that will ensure that call references are preferred over other reference 
		// types.  In this scenario, since the remote functions are different, there should be 2
		// nodes created in the tree, 1 for each reference.
		//

		String toAddress = "0x1000";
		builder.createEmptyFunction("Function_1000", toAddress, 1, new VoidDataType());
		builder.addBytesFallthrough(firstCalledFunctionAddress);
		builder.disassemble(firstCalledFunctionAddress, 2);

		String secondToAddress = "0x2000";

		// create non-call read reference
		builder.createMemoryReference(firstCalledFunctionAddress, toAddress, RefType.READ,
			SourceType.USER_DEFINED);

		// create call reference at a different op index so both references can co-exist
		builder.tx(() -> {
			ReferenceManager refManager = program.getReferenceManager();
			Reference ref =
				refManager.addMemoryReference(addr(firstCalledFunctionAddress),
					addr(secondToAddress), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 1);
			return ref;
		});

		List<GTreeNode> children = node1.generateChildren(TaskMonitor.DUMMY);
		assertEquals(2, children.size());
	}

//=================================================================================================
// Private Methods
//=================================================================================================

	private Address addr(String addrString) {
		return builder.addr(addrString);
	}

	private void createThunkFunctionCallGraph() throws Exception {

		/*
		 	
			node1
			0010 -> Function @ 0100
			
				node2
				Call: 0100 -> Thunk_Function_1050 @ 1050
				
					node3
					Call: 1050 -> Function_1100 @ 1100
					
						node4
						Call: 1100 -> 1200
		 */

		String thunkedAddress = "0x1100";
		Function thunkedFunction =
			builder.createEmptyFunction("Function_1100", thunkedAddress, 10, DataType.DEFAULT);
		builder.createMemoryCallReference("0x1100", "0x1200"); // ref so a node appears in the tree

		String thunkAddress = "0x1050";
		Function thunkFunction =
			builder.createEmptyFunction("Thunk_Function_1050", thunkAddress, 10, DataType.DEFAULT);
		tx(() -> {
			thunkFunction.setThunkedFunction(thunkedFunction);
		});

		builder.createMemoryCallReference(firstCalledFunctionAddress, thunkAddress);
		builder.createMemoryCallReference(thunkAddress, thunkedAddress);
	}

	private void setUpCallNodeWithThunksHidden() {

		FunctionManager fm = program.getFunctionManager();
		Function firstCalledFunction = fm.getFunctionAt(builder.addr(firstCalledFunctionAddress)); // 0x0100
		Address calledFromAddress = builder.addr(firstCallSourceAddress); // 0x0010
		CallTreeOptions callTreeOptions = new CallTreeOptions();
		callTreeOptions = callTreeOptions.withRecurseDepth(5);
		callTreeOptions = callTreeOptions.withFilterThunks(true);
		node1 =
			new OutgoingCallNode(program, firstCalledFunction, calledFromAddress, true,
				callTreeOptions);

	}

	private <E extends Exception> void tx(ExceptionalCallback<E> c) {
		int txId = program.startTransaction("Test - Function in Transaction");
		boolean commit = true;
		try {
			c.call();
			program.flushEvents();
		}
		catch (Exception e) {
			commit = false;
			failWithException("Exception modifying program '" + program.getName() + "'", e);
		}
		finally {
			program.endTransaction(txId, commit);
		}
	}

	private void createCallInstruction() throws Exception {
		Address source = builder.addr(firstCalledFunctionAddress);
		Address destination = source.add(1);
		builder.addBytesCall(source.getOffset(), destination.getOffset());
		builder.disassemble(firstCalledFunctionAddress, 2);

		//
		// Note: the tests that use this are creating their references to control the code's
		//       execution path, so get rid of the default reference created for this instruction
		//
		int txID = program.startTransaction("Remove References");
		try {
			ReferenceManager rm = program.getReferenceManager();
			rm.removeAllReferencesFrom(builder.addr(firstCalledFunctionAddress));
		}
		finally {
			program.endTransaction(txID, true);
		}
	}
}
