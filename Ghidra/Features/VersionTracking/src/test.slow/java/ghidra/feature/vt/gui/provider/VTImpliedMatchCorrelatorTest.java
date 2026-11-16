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
package ghidra.feature.vt.gui.provider;

import static org.junit.Assert.*;

import java.util.Collection;
import java.util.List;

import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.db.VTTestUtils;
import ghidra.feature.vt.gui.task.AcceptMatchTask;
import ghidra.feature.vt.gui.task.ApplyMatchTask;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class VTImpliedMatchCorrelatorTest extends AbstractVTCorrelatorTest {

	public VTImpliedMatchCorrelatorTest() {
		super("VersionTracking/WallaceSrc.gzf", "VersionTracking/WallaceVersion2.gzf");
	}

	/*
	 * Run the Exact Function Bytes Match correlator and accept all matches,
	 * then check to see that the expected implied matches are created
	 */
	@Test
	public void testImpliedMatches_ExactFunctionBytesMatch() throws Exception {

		// Run the Exact Function Correlator
		String exactMatchCorrelator = "Exact Function Bytes Match";
		runTestCorrelator(exactMatchCorrelator);

		VTMatchSet matchSet = getVTMatchSet(exactMatchCorrelator);
		ApplyMatchTask task =
			new ApplyMatchTask(controller, (List<VTMatch>) matchSet.getMatches());
		runTask(task);

		// get the matches only from the correlator just run
		VTMatchSet impliedMatchSet = getVTMatchSet("Implied Match");
		assertNotNull(impliedMatchSet);

		// now test the expected matches which are real functions or data, not thunks
		// if all are in set and we tested the size then no thunks are in the set
		assertEquals(18, impliedMatchSet.getMatchCount());
		assertInMatchSet("00400000", "00400000", impliedMatchSet);
		assertInMatchSet("0040003c", "0040003c", impliedMatchSet);
		assertInMatchSet("004000e0", "004000d0", impliedMatchSet);
		assertInMatchSet("004000f8", "004000e8", impliedMatchSet);
		assertInMatchSet("00400154", "00400144", impliedMatchSet);
		assertInMatchSet("004001c8", "004001b8", impliedMatchSet);
		assertInMatchSet("004123f0", "004123d0", impliedMatchSet);
		assertInMatchSet("00416a84", "00416a84", impliedMatchSet);
		assertInMatchSet("00416a9c", "00416a9c", impliedMatchSet);
		assertInMatchSet("00416dbc", "00416dbc", impliedMatchSet);
		assertInMatchSet("0041713c", "0041713c", impliedMatchSet);
		assertInMatchSet("004176cc", "004176cc", impliedMatchSet);
		assertInMatchSet("004176d0", "004176cc", impliedMatchSet);
		assertInMatchSet("004178d8", "004178d8", impliedMatchSet);
		assertInMatchSet("00418008", "00418008", impliedMatchSet);
		assertInMatchSet("00418168", "00418168", impliedMatchSet);
		assertInMatchSet("0041816c", "0041816c", impliedMatchSet);
		assertInMatchSet("00418174", "00418174", impliedMatchSet);
	}

	/*
	 * Run the Exact Function Instructions Match correlator and accept all matches,
	 * then make sure there are no implied match thunks
	 */
	@Test
	public void testImpliedMatches_NoThunks_ExactInstructionBytesMatch() throws Exception {

		// Run the Exact Function Correlator
		String exactMatchCorrelator = "Exact Function Instructions Match";
		runTestCorrelator(exactMatchCorrelator);

		VTMatchSet matchSet = getVTMatchSet(exactMatchCorrelator);
		ApplyMatchTask task =
			new ApplyMatchTask(controller, (List<VTMatch>) matchSet.getMatches());
		runTask(task);

		// get the matches only from the correlator just run
		VTMatchSet impliedMatchSet = getVTMatchSet("Implied Match");
		assertNotNull(impliedMatchSet);

		// too many to check them all individually so iterate over all the matches and test to see
		// that none are thunks
		FunctionManager srcFunctionMgr = session.getSourceProgram().getFunctionManager();
		FunctionManager destFunctionMgr = session.getDestinationProgram().getFunctionManager();

		Collection<VTMatch> matches = impliedMatchSet.getMatches();
		for (VTMatch match : matches) {
			if (!match.getAssociation().getType().equals(VTAssociationType.FUNCTION)) {
				continue;
			}

			Address srcAddr = match.getSourceAddress();
			Function sourceFunc = srcFunctionMgr.getFunctionAt(srcAddr);
			Address destAddr = match.getDestinationAddress();
			Function destFunc = destFunctionMgr.getFunctionAt(destAddr);
			assertFalse(sourceFunc.getEntryPoint() + "is a thunk!", sourceFunc.isThunk());
			assertFalse(destFunc.getEntryPoint() + "is a thunk!", destFunc.isThunk());
		}
	}

	/*
	 * Test to make sure that implied matches are not created when there is already
	 * the same match made by another correlator. Check the number of votes were incremented
	 */
	@Test
	public void testNoImpliedMatchesForExistingMatches() throws Exception {

		runTestCorrelator("Exact Symbol Name Match");
		runTestCorrelator("Exact Function Instructions Match");

		// accept just the "addPeople" function match which will attempt to create implied
		// matches just for this match

		// Note: This function has the implied matches that were all already found by either the
		// symbol name correlator or the exact function instruction match correlator so we do not
		// expect to have any implied matches created. However, the vote count for the matches that
		// would have been implied matches should now be 1
		VTMatch match = createMatch(saddr("0x411700"), daddr("0x004116f0"));

		AcceptMatchTask task = new AcceptMatchTask(controller, List.of(match));
		runTask(task);
		assertImpliedMatchCount(0);

		assertVoteCount(1, saddr("0x00411860"), daddr("0x00411830")); // addPerson 
		assertVoteCount(1, saddr("0x004168a0"), daddr("0x004168a0")); // s_Lord_Victor_Quartermaine
		assertVoteCount(1, saddr("0x0041688c"), daddr("0x0041688c")); // s_Lady_Tottington 
		assertVoteCount(1, saddr("0x004168a0"), daddr("0x004168a0")); // s_Were_Rabbit 
		assertVoteCount(1, saddr("0x0041687c"), daddr("0x0041687c")); // s_Rabbit 
		assertVoteCount(1, saddr("0x00416874"), daddr("0x00416874")); // s_Wallace 
		assertVoteCount(1, saddr("0x00411b80"), daddr("0x00411b60")); // __RTC_CheckEsp 	

	}

	@Test
	public void testBlockImpliedMatchesWithConflicts() throws Exception {

		/*
		 	 This tests was written to test a bug that allowed implied matches to not be considered
		 	 blocked as the user accepted matches.
		 */

		setUpProgram_ImpliedMatchBlockScenario_SourceProgram();
		setUpProgram_ImpliedMatchBlockScenario_DestinationProgram();

		/*
		 	Source and Destination each have identical functions at:
		 	
		 		0x00414000
		 		0x00414010
		 		0x00414020
		 		0x00414100
		 		0x00414110
		 */

		Address srcFunction1 = saddr("0x00414000");
		Address destFunction1 = daddr("0x00414000");

		Address destFunction2 = daddr("0x00414010");

		Address destFunction3 = daddr("0x00414020");

		Address srcFunction4 = saddr("0x00414100");
		Address destFunction4 = daddr("0x00414100");

		Address srcFunction5 = saddr("0x00414110");
		Address destFunction5 = daddr("0x00414110");

		// Apply the function1 match. There should be no implied matches, since these functions do
		// not share references to other matched functions.
		VTMatch match = createMatch(srcFunction1, destFunction1);
		Task task = new AcceptMatchTask(controller, List.of(match));
		runTask(task);
		assertImpliedMatchCount(0);

		// now apply function4 match to create an implied match for function1 -> function2
		match = createMatch(srcFunction4, destFunction4);
		task = new AcceptMatchTask(controller, List.of(match));
		runTask(task);
		assertImpliedMatchCount(1);
		assertBlocked(srcFunction1, destFunction2);

		// now apply function5 match to create an implied match for function1 -> function3
		match = createMatch(srcFunction5, destFunction5);
		task = new AcceptMatchTask(controller, List.of(match));
		runTask(task);
		assertImpliedMatchCount(2);
		assertBlocked(srcFunction1, destFunction3);
	}

	// program with 5 source program functions to simulate block implied match test - source prog
	private void setUpProgram_ImpliedMatchBlockScenario_SourceProgram()
			throws Exception {

		int txId = srcProg.startTransaction("Test");

		// function 1 mov, eax 1 5nops
		byte[] bytes = { (byte) 0xB8, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xC3 };
		Address address1 = addr(srcProg, "0x00414000");
		srcProg.getMemory().setBytes(address1, bytes);

		// function 2 mov, eax 1 6nops
		byte[] bytes2 =
			{ (byte) 0xB8, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x90,
				(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xC3 };
		Address address2 = addr(srcProg, "0x00414010");
		srcProg.getMemory().setBytes(address2, bytes2);

		// function 3 mov, eax 1 7nops
		byte[] bytes3 = { (byte) 0xB8, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90,
			(byte) 0x90, (byte) 0xC3 };
		Address address3 = addr(srcProg, "0x00414020");
		srcProg.getMemory().setBytes(address3, bytes3);

		// function 4 push 0x414000, 4nops
		byte[] bytes4 = { (byte) 0x68, (byte) 0x00, (byte) 0x40, (byte) 0x41, (byte) 0x00,
			(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xC3 };
		Address address4 = addr(srcProg, "0x00414100");
		srcProg.getMemory().setBytes(address4, bytes4);

		// function 5 push 0x414000, 5nops
		byte[] bytes5 = { (byte) 0x68, (byte) 0x00, (byte) 0x40, (byte) 0x41, (byte) 0x00,
			(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xC3 };
		Address address5 = addr(srcProg, "0x00414110");
		srcProg.getMemory().setBytes(address5, bytes5);

		disassemble(srcProg, address1);
		disassemble(srcProg, address2);
		disassemble(srcProg, address3);
		disassemble(srcProg, address4);
		disassemble(srcProg, address5);

		createFunction(srcProg, address1, "function1");
		createFunction(srcProg, address2, "function2");
		createFunction(srcProg, address3, "function3");
		createFunction(srcProg, address4, "function4");
		createFunction(srcProg, address5, "function5");

		srcProg.endTransaction(txId, true);

		srcProg.flushEvents();
		waitForTasks();

	}

	// program with 5 dest program functions to simulate block implied match test
	private void setUpProgram_ImpliedMatchBlockScenario_DestinationProgram()
			throws Exception {

		int txId = destProg.startTransaction("Test");

		// function 1 mov, eax 1 5nops
		byte[] bytes = { (byte) 0xB8, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xC3 };
		Address address1 = addr(destProg, "0x00414000");
		destProg.getMemory().setBytes(address1, bytes);

		// function 2 mov, eax 1 6nops
		byte[] bytes2 =
			{ (byte) 0xB8, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x90,
				(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xC3 };
		Address address2 = addr(destProg, "0x00414010");
		destProg.getMemory().setBytes(address2, bytes2);

		// function 3 mov, eax 1 7nops
		byte[] bytes3 = { (byte) 0xB8, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90,
			(byte) 0x90, (byte) 0xC3 };
		Address address3 = addr(destProg, "0x00414020");
		destProg.getMemory().setBytes(address3, bytes3);

		// function 4 push 0x414000, 4nops
		byte[] bytes4 = { (byte) 0x68, (byte) 0x10, (byte) 0x40, (byte) 0x41, (byte) 0x00,
			(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xC3 };
		Address address4 = addr(destProg, "0x00414100");
		destProg.getMemory().setBytes(address4, bytes4);

		// function 5 push 0x414000, 5nops
		byte[] bytes5 = { (byte) 0x68, (byte) 0x20, (byte) 0x40, (byte) 0x41, (byte) 0x00,
			(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xC3 };
		Address address5 = addr(destProg, "0x00414110");
		destProg.getMemory().setBytes(address5, bytes5);

		disassemble(destProg, address1);
		disassemble(destProg, address2);
		disassemble(destProg, address3);
		disassemble(destProg, address4);
		disassemble(destProg, address5);

		createFunction(destProg, address1, "function1");
		createFunction(destProg, address2, "function2");
		createFunction(destProg, address3, "function3");
		createFunction(destProg, address4, "function4");
		createFunction(destProg, address5, "function5");

		destProg.endTransaction(txId, true);

		destProg.flushEvents();
		waitForTasks();

	}

	private VTMatch createMatch(Address sourceAddress, Address destinationAddress) {

		VTProgramCorrelator correlator =
			VTTestUtils.createProgramCorrelator(srcProg, destProg);

		String transactionName = "Blocked Test";
		int startTransaction = session.startTransaction(transactionName);

		VTMatchSet matchSet = session.createMatchSet(correlator);
		VTMatchInfo info = new VTMatchInfo(matchSet);

		info.setAssociationType(VTAssociationType.FUNCTION);
		info.setSourceAddress(sourceAddress);
		info.setDestinationAddress(destinationAddress);
		VTScore confidence = new VTScore(10.0);
		info.setConfidenceScore(confidence);
		VTScore score = new VTScore(1.0);
		info.setSimilarityScore(score);
		long sourceLen = srcProg.getFunctionManager()
				.getFunctionAt(sourceAddress)
				.getBody()
				.getNumAddresses();
		long destLen = destProg.getFunctionManager()
				.getFunctionAt(destinationAddress)
				.getBody()
				.getNumAddresses();
		info.setSourceLength((int) sourceLen);
		info.setDestinationLength((int) destLen);
		matchSet.addMatch(info);
		assertNotNull(matchSet);
		VTMatch match = getMatch(matchSet, sourceAddress, destinationAddress);
		assertNotNull(match);

		session.endTransaction(startTransaction, true);

		session.flushEvents();
		waitForTasks();

		return match;
	}

	private boolean disassemble(Program program, Address address) {
		DisassembleCommand cmd = new DisassembleCommand(address, null, true);
		return cmd.applyTo(program, TaskMonitor.DUMMY);
	}

	private Function createFunction(Program program, Address entryPoint, String name) {
		CreateFunctionCmd cmd = new CreateFunctionCmd(name, entryPoint, null,
			name != null ? SourceType.USER_DEFINED : SourceType.DEFAULT);
		if (cmd.applyTo(program, TaskMonitor.DUMMY)) {
			return program.getListing().getFunctionAt(entryPoint);
		}
		return null;
	}

	private void assertImpliedMatchCount(int expected) {
		VTMatchSet impliedMatchSet = getVTMatchSet("Implied Match");
		int actual = impliedMatchSet.getMatchCount();
		if (expected != actual) {
			Msg.debug(this, "Expectd " + expected + ", but found " + actual);
			Collection<VTMatch> matches = impliedMatchSet.getMatches();
			for (VTMatch match : matches) {
				Msg.debug(this, "Implied match: " + match);
			}

			fail();
		}
	}

	private void assertBlocked(Address src, Address dest) {
		VTAssociationManager associationMgr = session.getAssociationManager();
		VTAssociation impliedAssociation = associationMgr.getAssociation(src, dest);
		assertEquals(VTAssociationStatus.BLOCKED, impliedAssociation.getStatus());
	}

	private void assertVoteCount(int expected, Address saddr, Address daddr) {
		VTAssociationManager associationManager = session.getAssociationManager();
		assertEquals(expected, associationManager.getAssociation(saddr, daddr).getVoteCount());
	}

	private void assertInMatchSet(String srcAddr, String destAddr, VTMatchSet matchSet) {
		assertTrue(isMatchInMatchSet(saddr(srcAddr), daddr(destAddr), matchSet));
	}

	private boolean isMatchInMatchSet(Address srcAddr, Address destAddr, VTMatchSet matchSet) {
		if (matchSet.getMatches(srcAddr, destAddr).size() > 0) {
			return true;
		}
		return false;
	}

	private Address saddr(String s) {
		return addr(srcProg, s);
	}

	private Address daddr(String s) {
		return addr(destProg, s);
	}
}
