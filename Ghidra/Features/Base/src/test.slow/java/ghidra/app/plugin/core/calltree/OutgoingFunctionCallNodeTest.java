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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGenericTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

/**
 * This test class is covering the various types of 'calls' a function can make, such as a 
 * direct call instruction, or through a user-defined reference.   External calls are also a bit
 * tricky.   This test was created by following the code paths in {@link OutgoingFunctionCallNode}
 * and making sure that each path was followed.
 */
public class OutgoingFunctionCallNodeTest extends AbstractGenericTest {

	private ToyProgramBuilder builder;
	private Program program;
	private OutgoingFunctionCallNode node;
	private String nodeAddress = "0x0000";

	public OutgoingFunctionCallNodeTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		builder = new ToyProgramBuilder("Call Node Test", true);
		builder.createMemory(".text", "0x0", 0x3000);

		Function function = builder.createFunction(nodeAddress);

		program = builder.getProgram();

		Address source = builder.addr("0x1000"); // fake
		node = new OutgoingFunctionCallNode(program, function, source, true, new AtomicInteger(5));
	}

	@Test
	public void testGenerateChildren_SelfRecursiveCall() throws Exception {

		builder.createMemoryCallReference(nodeAddress, nodeAddress);

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_CalledFunctionExists() throws Exception {
		String otherAddress = "0x1000";
		builder.createEmptyFunction("Function_2", otherAddress, 10, DataType.DEFAULT);
		builder.createMemoryCallReference(nodeAddress, otherAddress);

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertEquals("Function_2", children.get(0).getName());
	}

	@Test
	public void testGenerateChildren_CalledFunctionExists_ExternalCall() throws Exception {
		String otherAddress = "0x1000";

		String externalFunctionName = "External_Function";
		ExternalLocation location =
			builder.createExternalFunction(otherAddress, "ExternalLibrary", externalFunctionName);

		builder.createMemoryCallReference(nodeAddress,
			location.getExternalSpaceAddress().toString());

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertEquals(externalFunctionName, children.get(0).getName());
	}

	@Test
	public void testGenerateChildren_CallReference_ExternalFunction_NoFunctionInMemory()
			throws Exception {

		builder.createMemoryCallReference(nodeAddress, "EXTERNAL:00000001");

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
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

		Reference ref = builder.createMemoryCallReference(nodeAddress, "0x2000");

		Address toAddress = ref.getToAddress();
		builder.applyDataType(toAddress.toString(), new Pointer32DataType());

		String externalFunctionName = "External_Function";
		ExternalLocation location =
			builder.createExternalFunction("0x2020", "ExternalLibrary", externalFunctionName);

		builder.createMemoryReadReference(toAddress.toString(),
			location.getExternalSpaceAddress().toString());

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
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

		Reference ref = builder.createMemoryCallReference(nodeAddress, "0x2000");

		Address toAddress = ref.getToAddress();
		builder.applyDataType(toAddress.toString(), new Pointer32DataType());

		String functionAddress = "0x2020";
		builder.createEmptyFunction("Function_1", functionAddress, 1, new VoidDataType());

		builder.createMemoryReadReference(toAddress.toString(), functionAddress);

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
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
		builder.createMemoryCallReference(nodeAddress, offcutAddress);

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertTrue(children.get(0) instanceof DeadEndNode);
	}

	@Test
	public void testGenerateChildren_WriteReference() throws Exception {

		// 
		// Have a reference in the function to a place that is not another function, and the
		// reference is a write reference.  No call node is created.
		//

		builder.createMemoryReference(nodeAddress, "0x1000", RefType.WRITE,
			SourceType.USER_DEFINED);
		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
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

		builder.createMemoryReference(nodeAddress, "0x1000", RefType.READ, SourceType.USER_DEFINED);
		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());

	}

	@Test
	public void testGenerateChildren_ReadReference_NotCallInstruction() throws Exception {

		//
		// Read reference to an instruction with a flow type that is not a call
		//

		builder.addBytesFallthrough(nodeAddress);
		builder.disassemble(nodeAddress, 2);

		builder.createMemoryReference(nodeAddress, "0x1000", RefType.READ, SourceType.USER_DEFINED);
		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
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

		builder.createMemoryReference(nodeAddress, "0x1000", RefType.READ, SourceType.USER_DEFINED);
		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_CallInstruction_ToData_NoReference()
			throws Exception {

		//
		// Read reference from an instruction with a flow type of call.
		//

		createCallInstruction();

		builder.createMemoryReference(nodeAddress, "0x1000", RefType.READ, SourceType.USER_DEFINED);
		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_CallInstruction_ToData_NonExternalReference()
			throws Exception {

		//
		// Read reference from an instruction with a flow type that is a call, to a non-external place
		//

		createCallInstruction();

		builder.createMemoryReference(nodeAddress, "0x1000", RefType.READ, SourceType.USER_DEFINED);

		// put a non-external reference on the data at the 'to' address
		builder.createMemoryCallReference("0x1000", "0x1020");

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertTrue(children.isEmpty());
	}

	@Test
	public void testGenerateChildren_ReadReference_CallInstruction_ToData_ExternalReference_NonFunctionSymbol()
			throws Exception {

		//
		// Read reference from an instruction with a flow type that is a call, to a external place
		//

		createCallInstruction();

		builder.createMemoryReference(nodeAddress, "0x1000", RefType.READ, SourceType.USER_DEFINED);

		// put a external reference on the data at the 'to' address
		builder.createExternalReference("0x1000", "ExternalLib", "ExternalLabel", 0);

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
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

		builder.createMemoryReference(nodeAddress, "0x1000", RefType.READ, SourceType.USER_DEFINED);

		// put a external reference on the data at the 'to' address that calls the external function
		ExternalLocation location =
			builder.createExternalFunction("0x1020", "ExternalLib", "ExternalFunction_1");
		builder.createMemoryReadReference("0x1000", location.getExternalSpaceAddress().toString());

		List<GTreeNode> children = node.generateChildren(TaskMonitor.DUMMY);
		assertEquals(1, children.size());
		assertTrue(children.get(0) instanceof DeadEndNode);
	}

	private void createCallInstruction() throws Exception {
		builder.addBytesCall(0x0000, 0x1);
		builder.disassemble(nodeAddress, 2);

		//
		// Note: the tests that use this are creating their references to control the code's 
		//       execution path, so get rid of the default reference created for this instruction
		//
		int txID = program.startTransaction("Remove References");
		try {
			ReferenceManager rm = program.getReferenceManager();
			rm.removeAllReferencesFrom(builder.addr("0x0000"));
		}
		finally {
			program.endTransaction(txID, true);
		}
	}
}
