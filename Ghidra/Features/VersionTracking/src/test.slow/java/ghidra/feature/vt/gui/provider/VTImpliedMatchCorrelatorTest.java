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

import java.util.*;

import org.junit.Assert;
import org.junit.Test;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.db.VTTestUtils;
import ghidra.feature.vt.gui.task.ApplyMatchTask;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

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

		//Run the Exact Function Correlator
		String exactMatchCorrelator = "Exact Function Bytes Match";
		runTestCorrelator(exactMatchCorrelator);

		// apply all exact matches
		List<VTMatchSet> exactMatchSets = session.getMatchSets();
		for (VTMatchSet ms : exactMatchSets) {
			if (ms.getProgramCorrelatorInfo().getName().equals(exactMatchCorrelator)) {
				ApplyMatchTask task =
					new ApplyMatchTask(controller, (List<VTMatch>) ms.getMatches());
				runTask(task);
			}
		}

		//get the matches only from the correlator just run
		VTMatchSet testMatchSet = getVTMatchSet("Implied Match");

		Assert.assertNotEquals("vtMatchSet does not exist", null, testMatchSet);

		/* 
		 * Test that only non-thunks are in this set
		 */

		// first test the number of implied matches
		assertEquals(17, testMatchSet.getMatchCount());

		// now test the expected matches which are real functions or data, not thunks
		// if all are in set and we tested the size then no thunks are in the set
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "00400000"), addr(destProg, "00400000"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "0040003c"), addr(destProg, "0040003c"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "004000e0"), addr(destProg, "004000d0"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "004000f8"), addr(destProg, "004000e8"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "00400154"), addr(destProg, "00400144"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "004001c8"), addr(destProg, "004001b8"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "004123f0"), addr(destProg, "004123d0"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "00416a84"), addr(destProg, "00416a84"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "00416a9c"), addr(destProg, "00416a9c"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "00416dbc"), addr(destProg, "00416dbc"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "0041713c"), addr(destProg, "0041713c"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "004176cc"), addr(destProg, "004176cc"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "004176d0"), addr(destProg, "004176cc"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "004178d8"), addr(destProg, "004178d8"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "00418008"), addr(destProg, "00418008"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "00418168"), addr(destProg, "00418168"), testMatchSet));
		assertTrue(
			isMatchInMatchSet(addr(srcProg, "0041816c"), addr(destProg, "0041816c"), testMatchSet));
	}

	/*
	 * Run the Exact Function Instructions Match correlator and accept all matches, 
	 * then make sure there are no implied match thunks
	 */
	@Test
	public void testImpliedMatches_noThunks_ExactInstructionBytesMatch() throws Exception {

		//Run the Exact Function Correlator
		String exactMatchCorrelator = "Exact Function Instructions Match";
		runTestCorrelator(exactMatchCorrelator);

		// apply all exact matches
		List<VTMatchSet> exactMatchSets = session.getMatchSets();
		for (VTMatchSet ms : exactMatchSets) {
			if (ms.getProgramCorrelatorInfo().getName().equals(exactMatchCorrelator)) {
				ApplyMatchTask task =
					new ApplyMatchTask(controller, (List<VTMatch>) ms.getMatches());
				runTask(task);
			}
		}

		//get the matches only from the correlator just run
		VTMatchSet testMatchSet = getVTMatchSet("Implied Match");

		Assert.assertNotEquals("vtMatchSet does not exist", null, testMatchSet);

		/* 
		 * Test that only non-thunks are in this set
		 */

		// too many to check them all individually so iterate over all the matches and test to see 
		// that none are thunks				
		FunctionManager srcFunctionManager = session.getSourceProgram().getFunctionManager();
		FunctionManager destFunctionManager = session.getDestinationProgram().getFunctionManager();

		Collection<VTMatch> matches = testMatchSet.getMatches();
		for (VTMatch match : matches) {
			if (match.getAssociation().getType().equals(VTAssociationType.FUNCTION)) {
				Function sourceFunc = srcFunctionManager.getFunctionAt(match.getSourceAddress());
				Function destFunc =
					destFunctionManager.getFunctionAt(match.getDestinationAddress());
				assertTrue(sourceFunc.getEntryPoint().toString() + "is a thunk!",
					!sourceFunc.isThunk());
				assertTrue(destFunc.getEntryPoint().toString() + "is a thunk!",
					!destFunc.isThunk());
			}
		}
	}

	/*
	 * Test to make sure that implied matches are not created when there is already
	 * the same match made by another correlator. Check the number of votes were incremented
	 */
	@Test
	public void testNoImpliedMatchesForExistingMatches() throws Exception {

		// First Run the Exact Symbol Correlator to get all possible symbol name matches
		String exactSymbolMatchCorrelator = "Exact Symbol Name Match";
		runTestCorrelator(exactSymbolMatchCorrelator);

		// Now Run the Exact Function Instruction Correlator to get all possible exact instruction 
		// function matches
		String exactMatchCorrelator = "Exact Function Instructions Match";
		runTestCorrelator(exactMatchCorrelator);

		// accept/apply just the "addPeople" function match which will attempt to create implied 
		// matches just for this match

		// Note: This function has the implied matches that were all already found by either the 
		// symbol name correlator or the exact function instruction match correlator so we do not 
		// expect to have any implied matches created. However, the vote count for the matches that 
		// would have been implied matches should now be 1
		VTMatch match = createMatch(addr(srcProg, "0x411700"), addr(destProg, "0x004116f0"),
			srcProg, destProg, true);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);

		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		// get the resulting implied matches and verify that none of the matches that were already
		// created 
		VTMatchSet impliedMatchSet = getVTMatchSet("Implied Match");
		Assert.assertNotEquals("vtMatchSet does not exist", null, impliedMatchSet);

		// Now test that only the expected items are in this set for the given function we just 
		// applied
		assertEquals(0, impliedMatchSet.getMatchCount());

		VTAssociationManager associationManager = session.getAssociationManager();

		assertEquals(1, associationManager.getAssociation(addr(srcProg, "0x00411860"),
			addr(destProg, "0x00411830")).getVoteCount()); // addPerson 
		assertEquals(1, associationManager.getAssociation(addr(srcProg, "0x004168a0"),
			addr(destProg, "0x004168a0")).getVoteCount()); // s_Lord_Victor_Quartermaine 
		assertEquals(1, associationManager.getAssociation(addr(srcProg, "0x0041688c"),
			addr(destProg, "0x00041688c")).getVoteCount()); // s_Lady_Tottington 
		assertEquals(1, associationManager.getAssociation(addr(srcProg, "0x004168a0"),
			addr(destProg, "0x004168a0")).getVoteCount()); // s_Were_Rabbit 
		assertEquals(1, associationManager.getAssociation(addr(srcProg, "0x0041687c"),
			addr(destProg, "0x0041687c")).getVoteCount()); // s_Rabbit 
		assertEquals(1, associationManager.getAssociation(addr(srcProg, "0x00416874"),
			addr(destProg, "0x00416874")).getVoteCount()); // s_Wallace 
		assertEquals(1, associationManager.getAssociation(addr(srcProg, "0x00411b80"),
			addr(destProg, "0x00411b60")).getVoteCount()); // __RTC_CheckEsp 	

	}

	private VTMatch createMatch(Address sourceAddress, Address destinationAddress,
			Program sourceProgram, Program destinationProgram, boolean setAccepted)
			throws VTAssociationStatusException {
		VTProgramCorrelator correlator =
			VTTestUtils.createProgramCorrelator(null, sourceProgram, destinationProgram);

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
		long sourceLen = sourceProgram.getFunctionManager().getFunctionAt(
			sourceAddress).getBody().getNumAddresses();
		long destLen = destinationProgram.getFunctionManager().getFunctionAt(
			destinationAddress).getBody().getNumAddresses();
		info.setSourceLength((int) sourceLen);
		info.setDestinationLength((int) destLen);
		matchSet.addMatch(info);
		assertNotNull(matchSet);
		VTMatch match = getMatch(matchSet, sourceAddress, destinationAddress);
		assertNotNull(match);
		if (setAccepted) {
			match.getAssociation().setAccepted();
		}
		session.endTransaction(startTransaction, true);
		return match;
	}

	@Override
	protected VTMatch getMatch(VTMatchSet matches, Address sourceAddress,
			Address destinationAddress) {

		Iterator<VTMatch> it = matches.getMatches().iterator();
		while (it.hasNext()) {
			VTMatch match = it.next();
			if (match.getSourceAddress().equals(sourceAddress) &&
				match.getDestinationAddress().equals(destinationAddress)) {
				return match;
			}
		}
		return null;
	}

	public boolean isMatchInMatchSet(Address srcAddr, Address destAddr, VTMatchSet matchSet) {
		if (matchSet.getMatches(srcAddr, destAddr).size() > 0) {
			return true;
		}
		return false;
	}

}
