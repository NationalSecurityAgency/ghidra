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
package ghidra.app.plugin.core.select.flow;

import static org.junit.Assert.assertEquals;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.FollowFlow;
import ghidra.program.model.symbol.FlowType;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitorAdapter;

import org.junit.*;

public class FollowDelaySlotFlowTest extends AbstractFollowFlowTest {

	private ToyProgramBuilder programBuilder; // Instructions are 2-byte aligned 

	private int txId;

	@Override
	@Before
	public void setUp() throws Exception {
		programBuilder = new ToyProgramBuilder("Test", true, true, null);
		program = programBuilder.getProgram();
		txId = program.startTransaction("Add Memory"); // leave open until tearDown
		programBuilder.createMemory(".text", "0", 64).setExecute(true); // initialized
		programBuilder.createUninitializedMemory(".unint", "0x40", 64).setExecute(true); // uninitialized
		programBuilder.createUninitializedMemory(".dat", "0x80", 64); // no-execute
		programBuilder.createMemory(".text2", "0x3e0", 0x800).setExecute(true); // initialized
	}

	@Override
	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(txId, true);
		}
		if (programBuilder != null) {
			programBuilder.dispose();
		}
	}

	private Address address(long offset) {
		return programBuilder.getAddress(offset);
	}

	private String toHex(long value) {
		return Long.toHexString(value);
	}

	/**
	 * 
	 *     10: callds 20 --+
	 *     12: _or         |
	 *     14: ret         |
	 *                     |
	 *     20: or   <------+
	 *     22: ret
	 *     
	 * simple delay slot flow
	 */
	@Test
	public void testFlowConditionalDelaySlot() throws Exception {

		programBuilder.addBytesCallWithDelaySlot(10, 20);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesReturn(22);

		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(20), 4, false);

		Address addr = address(10);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(15));
		expectedAddresses.add(address(20), address(23));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *     10: or
	 *  +- 12: brds   20   
	 *  |  14: _or   <-----+
	 *  |  16: ret         |
	 *  |                  |
	 *  +->20: or          |
	 *     22: breq 14 ----+
	 *     24: ret
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testFlowIntoDelaySlotOfUnconditionalBranch() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranchConditional(22, 14);
		programBuilder.addBytesReturn(24);

		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 6, false);

		Address addr = address(20);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(14), address(17));
		expectedAddresses.add(address(20), address(25));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *     10: or
	 *  +- 12: brds   20   
	 *  |  14: _or   <-----+
	 *  |  16: ret         |
	 *  |                  |
	 *  +->20: or          |
	 *     22: breq 14 ----+
	 *     24: ret
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testFlowUnconditionalBranchDelaySlot() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranchConditional(22, 14);
		programBuilder.addBytesReturn(24);

		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 6, false);

		Address addr = address(10);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(15));
		expectedAddresses.add(address(20), address(25));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *      4: bral 14 ----+
	 *                     |
	 *     10: or          |
	 *  +- 12: brds   20   |
	 *  |  14: _or   <-----+     
	 *  |  16: ret
	 *  |         
	 *  +->20: ret   
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testFlowBranchIntoDelaySlotInProgram() throws Exception {

		programBuilder.addBytesBranch(4, 14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(20);

		programBuilder.disassemble(toHex(4), 2, false);
		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 2, false);

		Address addr = address(4);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(4), address(5));
		expectedAddresses.add(address(14), address(17));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *      4: bral 14 ----+
	 *                     |
	 *     10: or          |
	 *  +- 12: brds   20   |
	 *  |  14: _or   <-----+     
	 *  |  16: ret
	 *  |         
	 *  +->20: ret   
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testFlowBranchFromDelaySlotInProgram() throws Exception {

		programBuilder.addBytesBranch(4, 14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(20);

		programBuilder.disassemble(toHex(4), 2, false);
		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 2, false);

		Address addr = address(10);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(15));
		expectedAddresses.add(address(20), address(21));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 * 
	 *     10: callds 20 --+
	 *     12: _or         |
	 *     14: ret         |
	 *                     |
	 *     20: or   <------+
	 *     22: ret
	 *     
	 * simple delay slot flow
	 */
	@Test
	public void testBackwardFlowConditionalDelaySlotBranch() throws Exception {

		programBuilder.addBytesCallWithDelaySlot(10, 20);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesReturn(22);

		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(20), 4, false);

		Address addr = address(22);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(13));
		expectedAddresses.add(address(20), address(23));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 * 
	 *     10: callds 20 --+
	 *     12: _or         |
	 *     14: ret         |
	 *                     |
	 *     20: or   <------+
	 *     22: ret
	 *     
	 * simple delay slot flow
	 */
	@Test
	public void testBackwardFlowConditionalDelaySlotFallThrough() throws Exception {

		programBuilder.addBytesCallWithDelaySlot(10, 20);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesReturn(22);

		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(20), 4, false);

		Address addr = address(14);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(15));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *     10: or
	 *  +- 12: brds   20   
	 *  |  14: _or   <-----+
	 *  |  16: ret         |
	 *  |                  |
	 *  +->20: or          |
	 *     22: breq 14 ----+
	 *     24: ret
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testBackwardFlowBranchIntoDelaySlotBranch() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranchConditional(22, 14);
		programBuilder.addBytesReturn(24);

		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 6, false);

		Address addr = address(24);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(15));
		expectedAddresses.add(address(20), address(25));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *     10: or
	 *  +- 12: brds   20   
	 *  |  14: _or   <-----+
	 *  |  16: ret         |
	 *  |                  |
	 *  +->20: or          |
	 *     22: breq 14 ----+
	 *     24: ret
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testBackwardFlowBranchFromDelaySlotStart() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranchConditional(22, 14);
		programBuilder.addBytesReturn(24);

		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 6, false);

		Address addr = address(20);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(15));
		expectedAddresses.add(address(20), address(21));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *     10: or
	 *  +- 12: brds   20   
	 *  |  14: _or   <-----+
	 *  |  16: ret         |
	 *  |                  |
	 *  +->20: or          |
	 *     22: breq 14 ----+
	 *     24: ret
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testBackwardFlowBranchIntoDelaySlotFallThrough() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranchConditional(22, 14);
		programBuilder.addBytesReturn(24);

		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 6, false);

		Address addr = address(16);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(17));
		expectedAddresses.add(address(20), address(23));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *      4: bral 14 ----+
	 *                     |
	 *     10: or          |
	 *  +- 12: brds   20   |
	 *  |  14: _or   <-----+     
	 *  |  16: ret
	 *  |         
	 *  +->20: ret   
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testBackwardFlowWithBranchFromDelaySlot() throws Exception {

		programBuilder.addBytesBranch(4, 14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(20);

		programBuilder.disassemble(toHex(4), 2, false);
		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 2, false);

		Address addr = address(20);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(10), address(15));
		expectedAddresses.add(address(20), address(21));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *      4: bral 14 ----+
	 *                     |
	 *     10: or          |
	 *  +- 12: brds   20   |
	 *  |  14: _or   <-----+     
	 *  |  16: ret
	 *  |         
	 *  +->20: ret   
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testBackwardFlowWithBranchIntoDelaySlot() throws Exception {

		programBuilder.addBytesBranch(4, 14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(20);

		programBuilder.disassemble(toHex(4), 2, false);
		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 2, false);

		Address addr = address(16);
		AddressSet addressSet = new AddressSet(addr);
		FlowType[] flowsNotToFollow = new FlowType[] {};
		FollowFlow followFlow = new FollowFlow(program, addressSet, flowsNotToFollow); // FollowAllFlows
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(4), address(5));
		expectedAddresses.add(address(14), address(17));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *      4: bral 14 ----+
	 *                     |
	 *     10: or          |
	 *  +- 12: brds   20   |
	 *  |  14: _or   <-----+     
	 *  |  16: ret
	 *  |         
	 *  +->20: ret   
	 *     
	 * branch into delay slot
	 */
	@Test
	public void testBackwardFlowWithBranchIntoDelaySlotToNotFollow() throws Exception {

		programBuilder.addBytesBranch(4, 14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(20);

		programBuilder.disassemble(toHex(4), 2, false);
		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 2, false);

		Address addr = address(16);
		AddressSet addressSet = new AddressSet(addr);
		FollowFlow followFlow = new FollowFlow(program, addressSet, followOnlyPointers());
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(16), address(17));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *       4: bral 14 ----+
	 *                      |
	 *      10: or          |
	 *  +-- 12: brds   20   |
	 *  | +>14: _or   <-----+     
	 *  | | 16: ret
	 *  | |        
	 *  | +-20: bral 14   
	 *  +-->22: or   
	 *      24: ret   
	 *     
	 * multiple branches into delay slot
	 */
	@Test
	public void testBackwardFlowWithMultiBranchIntoDelaySlot() throws Exception {

		programBuilder.addBytesBranch(4, 14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 22);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesBranch(20, 14);
		programBuilder.addBytesFallthrough(22);
		programBuilder.addBytesReturn(24);

		programBuilder.disassemble(toHex(4), 2, false);
		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 6, false);

		Address addr = address(16);
		AddressSet addressSet = new AddressSet(addr);
		FollowFlow followFlow = new FollowFlow(program, addressSet, followAllFlows());
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(4), address(5));
		expectedAddresses.add(address(14), address(17));
		expectedAddresses.add(address(20), address(21));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}

	/**
	 *       4: bral 14 ----+
	 *                      |
	 *      10: or          |
	 *  +-- 12: brds   20   |
	 *  | +>14: _or   <-----+     
	 *  | | 16: ret
	 *  | |        
	 *  | +-20: brds 14   
	 *  +-->22: _or   
	 *      24: ret   
	 *     
	 * multiple branches into delay slot
	 */
	@Test
	public void testBackwardFlowWithMultiBranchIntoDelaySlotFromDelaySlot() throws Exception {

		programBuilder.addBytesBranch(4, 14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 22);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesBranchWithDelaySlot(20, 14);
		programBuilder.addBytesReturn(24);

		programBuilder.disassemble(toHex(4), 2, false);
		programBuilder.disassemble(toHex(10), 6, false);
		programBuilder.disassemble(toHex(16), 2, false);
		programBuilder.disassemble(toHex(20), 6, false);

		Address addr = address(16);
		AddressSet addressSet = new AddressSet(addr);
		FollowFlow followFlow = new FollowFlow(program, addressSet, followAllFlows());
		AddressSet flowAddresses = followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(address(4), address(5));
		expectedAddresses.add(address(14), address(17));
		expectedAddresses.add(address(20), address(23));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));

	}
}
