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

import static ghidra.feature.vt.api.main.VTAssociationType.DATA;
import static org.junit.Assert.assertTrue;

import java.util.*;

import org.junit.Assert;
import org.junit.Test;

import ghidra.feature.vt.api.correlator.program.VTAbstractReferenceProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.task.ApplyMatchTask;
import ghidra.program.model.address.Address;

public class VTCombinedFunctionDataReferenceCorrelator_x86_Test extends AbstractVTCorrelatorTest {

	private String testCorrelator = "Combined Function and Data Reference Match";

	public VTCombinedFunctionDataReferenceCorrelator_x86_Test() {
		super("VersionTracking/WallaceSrc.gzf", "VersionTracking/WallaceVersion2.gzf");
	}

	/*
	* Specify 3 known data matches, then run the Combined Data/Function Reference Correlator
	* and test that only the print function matches.
	*/
	@Test
	public void testCombinedReferenceCorrelator_onlyPrintDataMatches() throws Exception {

		// First create associated matches for the Reference correlator to work with.

		List<VTAssociationPair> associations = new ArrayList<>();

		//s_%s_%s_deployed_on_%s__00416830
		associations.add(associate(addr(srcProg, "00416830"), addr(destProg, "00416830"),
			VTAssociationType.DATA));
		//s_anyone_0041684c
		associations.add(associate(addr(srcProg, "0041684c"), addr(destProg, "0041684c"),
			VTAssociationType.DATA));
		//s_is_not_00416858
		associations.add(associate(addr(srcProg, "00416858"), addr(destProg, "00416858"),
			VTAssociationType.DATA));

		// Create matches
		VTMatchSet matchSet = createMatchSet(session, associations);

		// apply the matches created above 
		Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}

		//Run the Combined Function and Data Reference Correlator
		runTestCorrelator(testCorrelator);

		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();
		expectedMatchPairs.add(associate(addr(srcProg, "004115d0"), addr(destProg, "004115c0")));  // src:print dst: print

		assertMatchPairs(expectedMatchPairs, testMatchPairs);
	}

	/*
	* Run the Exact Data Match correlator and accept all matches, 
	* then run the Data Reference Correlator and accept all matches
	* then run the Combined Data and Function reference correlator and test
	* that only the expected matches are found for the Default Options
	*/
	@Test
	public void testCombinedReferenceCorrelator_allDataAndFunctionMatchesDefaultOptions()
			throws Exception {
		//Run Exact Data and Exact Function Match Correlators
		String exactDataMatchCorrelator = "Exact Data Match";
		String exactFunctionMatchCorrelator = "Exact Function Instructions Match";

		runTestCorrelator(exactDataMatchCorrelator);
		runTestCorrelator(exactFunctionMatchCorrelator);

		// apply all exact matches
		List<VTMatchSet> exactMatchSets = session.getMatchSets();
		for (VTMatchSet ms : exactMatchSets) {
			String corrName = ms.getProgramCorrelatorInfo().getName();
			if (corrName == exactDataMatchCorrelator || corrName == exactFunctionMatchCorrelator) {
				ApplyMatchTask task =
					new ApplyMatchTask(controller, (List<VTMatch>) ms.getMatches());
				runTask(task);
			}
		}

		runTestCorrelatorWithDefaultOptions(testCorrelator);

		//get the matches only from the correlator just run
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches

		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();

		expectedMatchPairs.add(associate(addr(srcProg, "004115d0"), addr(destProg, "004115c0")));  // src:print dst: print
		expectedMatchPairs.add(associate(addr(srcProg, "00411700"), addr(destProg, "004116f0")));  // src:addPeople dst: addPeople
		expectedMatchPairs.add(associate(addr(srcProg, "00411860"), addr(destProg, "00411830")));  // src:addPerson dst: addPerson
		expectedMatchPairs.add(associate(addr(srcProg, "004118f0"), addr(destProg, "004118c0")));  // src:deployGadget dst: FUN_004118c0		

		expectedMatchPairs.add(associate(addr(srcProg, "00411a30"), addr(destProg, "00411a10")));  // src:main dst: main

		expectedMatchPairs.add(associate(addr(srcProg, "00411b80"), addr(destProg, "00411b60")));  // src:__RTC_CheckEsp dst: __RTC_CheckEsp		
		expectedMatchPairs.add(associate(addr(srcProg, "00411bb0"), addr(destProg, "00411b90")));  // src:@_RTC_CheckStackVars@8 dst: @_RTC_CheckStackVars@8
		expectedMatchPairs.add(associate(addr(srcProg, "00411c70"), addr(destProg, "00411c50")));  // src:@_RTC_CheckStackVars2@12 dst: @_RTC_CheckStackVars2@12		
		expectedMatchPairs.add(associate(addr(srcProg, "00411dc0"), addr(destProg, "00411da0")));  // src:FUN_00411dc0 dst: FUN_00411da0		
//		expectedMatchPairs.add(associate(addr(srcProg, "00411e70"), addr(destProg, "00411e50")));  // src:FUN_00411e70 dst: FUN_00411e50 -- similarity score < 0.5	
		expectedMatchPairs.add(associate(addr(srcProg, "00411ee0"), addr(destProg, "00411ec0")));  // src:_mainCRTStartup dst: _mainCRTStartup

//		expectedMatchPairs.add(associate(addr(srcProg, "00411f00"), addr(destProg, "00411ee0")));  // src:___tmainCRTStartup dst: ___tmainCRTStartup -- similarity score < 0.5		

		expectedMatchPairs.add(associate(addr(srcProg, "004122b0"), addr(destProg, "00412290")));  // src:__RTC_GetErrDesc dst: __RTC_GetErrDesc
		expectedMatchPairs.add(associate(addr(srcProg, "00412380"), addr(destProg, "00412360")));  // src:_RTC_Failure dst: _RTC_Failure
		expectedMatchPairs.add(associate(addr(srcProg, "004123f0"), addr(destProg, "004123d0")));  // src:failwithmessage dst: failwithmessage
		expectedMatchPairs.add(associate(addr(srcProg, "00412810"), addr(destProg, "004127f0")));  // src:_RTC_StackFailure dst: _RTC_StackFailure
		expectedMatchPairs.add(associate(addr(srcProg, "00412950"), addr(destProg, "00412930")));  // src:_RTC_AllocaFailure dst: _RTC_AllocaFailure
		expectedMatchPairs.add(associate(addr(srcProg, "00412ad0"), addr(destProg, "00412ab0")));  // src:_getMemBlockDataString dst: _getMemBlockDataString
		expectedMatchPairs.add(associate(addr(srcProg, "00412b60"), addr(destProg, "00412b40")));  // src:__RTC_UninitUse dst: __RTC_UninitUse
		expectedMatchPairs.add(associate(addr(srcProg, "00412e90"), addr(destProg, "00412e70")));  // src:__setdefaultprecision dst: __setdefaultprecision

//		expectedMatchPairs.add(associate(addr(srcProg, "00412fa0"), addr(destProg, "00412f80")));  // src:__onexit dst: __onexit -- similarity score < 0.5	

		expectedMatchPairs.add(associate(addr(srcProg, "004130d0"), addr(destProg, "004130b0")));  // src:_atexit dst: _atexit
		expectedMatchPairs.add(associate(addr(srcProg, "00413370"), addr(destProg, "00413350")));  // src:__IsNonwritableInCurrentImage dst: __IsNonwritableInCurrentImage
		expectedMatchPairs.add(associate(addr(srcProg, "004134e0"), addr(destProg, "004134c0")));  // src: FUN_004134e0 dst: FUN_004134c0
		expectedMatchPairs.add(associate(addr(srcProg, "00413520"), addr(destProg, "00413500")));  // src:_RTC_GetSrcLine dst: _RTC_GetSrcLine
		expectedMatchPairs.add(associate(addr(srcProg, "00413890"), addr(destProg, "00413870")));  // src:GetPdbDll dst: GetPdbDll

		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}

	/*
	* Run the Exact Data Match correlator and accept all matches, 
	* then run the Data Reference Correlator and accept all matches
	* then run the Combined Data and Function reference correlator 
	* with lowered similarity score and Refine Results turned off
	* then test that only the expected matches are found
	*/
	@Test
	public void testCombinedReferenceCorrelator_allDataAndFunctionMatchesAdjustedOptions()
			throws Exception {
		//Run Exact Data and Exact Function Match Correlators
		String exactDataMatchCorrelator = "Exact Data Match";
		String exactFunctionMatchCorrelator = "Exact Function Instructions Match";

		runTestCorrelator(exactDataMatchCorrelator);
		runTestCorrelator(exactFunctionMatchCorrelator);

		// apply all exact matches
		List<VTMatchSet> exactMatchSets = session.getMatchSets();
		for (VTMatchSet ms : exactMatchSets) {
			String corrName = ms.getProgramCorrelatorInfo().getName();
			if (corrName == exactDataMatchCorrelator || corrName == exactFunctionMatchCorrelator) {
				ApplyMatchTask task =
					new ApplyMatchTask(controller, (List<VTMatch>) ms.getMatches());
				runTask(task);
			}
		}

		//runTestCorrelator(testCorrelator);
		runTestReferenceCorrelatorWithOptions(testCorrelator, 1.0,
			VTAbstractReferenceProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT, 0.1, true);

		//get the matches only from the correlator just run
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches

		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();

		expectedMatchPairs.add(associate(addr(srcProg, "004115d0"), addr(destProg, "004115c0")));  // src:print dst: print
		expectedMatchPairs.add(associate(addr(srcProg, "00411700"), addr(destProg, "004116f0")));  // src:addPeople dst: addPeople
		expectedMatchPairs.add(associate(addr(srcProg, "00411860"), addr(destProg, "00411830")));  // src:addPerson dst: addPerson
		expectedMatchPairs.add(associate(addr(srcProg, "004118f0"), addr(destProg, "004118c0")));  // src:deployGadget dst: FUN_004118c0		

		expectedMatchPairs.add(associate(addr(srcProg, "00411a30"), addr(destProg, "00411a10")));  // src:main dst: main

		expectedMatchPairs.add(associate(addr(srcProg, "00411b80"), addr(destProg, "00411b60")));  // src:__RTC_CheckEsp dst: __RTC_CheckEsp		
		expectedMatchPairs.add(associate(addr(srcProg, "00411bb0"), addr(destProg, "00411b90")));  // src:@_RTC_CheckStackVars@8 dst: @_RTC_CheckStackVars@8
		expectedMatchPairs.add(associate(addr(srcProg, "00411c70"), addr(destProg, "00411c50")));  // src:@_RTC_CheckStackVars2@12 dst: @_RTC_CheckStackVars2@12		
		expectedMatchPairs.add(associate(addr(srcProg, "00411dc0"), addr(destProg, "00411da0")));  // src:FUN_00411dc0 dst: FUN_00411da0		
		expectedMatchPairs.add(associate(addr(srcProg, "00411e70"), addr(destProg, "00411e50")));  // src:FUN_00411e70 dst: FUN_00411e50 -- similarity score < 0.5	
		expectedMatchPairs.add(associate(addr(srcProg, "00411ee0"), addr(destProg, "00411ec0")));  // src:_mainCRTStartup dst: _mainCRTStartup

		expectedMatchPairs.add(associate(addr(srcProg, "00411f00"), addr(destProg, "00411ee0")));  // src:___tmainCRTStartup dst: ___tmainCRTStartup -- similarity score < 0.5		

		expectedMatchPairs.add(associate(addr(srcProg, "004122b0"), addr(destProg, "00412290")));  // src:__RTC_GetErrDesc dst: __RTC_GetErrDesc
		expectedMatchPairs.add(associate(addr(srcProg, "00412380"), addr(destProg, "00412360")));  // src:_RTC_Failure dst: _RTC_Failure
		expectedMatchPairs.add(associate(addr(srcProg, "004123f0"), addr(destProg, "004123d0")));  // src:failwithmessage dst: failwithmessage
		expectedMatchPairs.add(associate(addr(srcProg, "00412810"), addr(destProg, "004127f0")));  // src:_RTC_StackFailure dst: _RTC_StackFailure
		expectedMatchPairs.add(associate(addr(srcProg, "00412950"), addr(destProg, "00412930")));  // src:_RTC_AllocaFailure dst: _RTC_AllocaFailure
		expectedMatchPairs.add(associate(addr(srcProg, "00412ad0"), addr(destProg, "00412ab0")));  // src:_getMemBlockDataString dst: _getMemBlockDataString
		expectedMatchPairs.add(associate(addr(srcProg, "00412b60"), addr(destProg, "00412b40")));  // src:__RTC_UninitUse dst: __RTC_UninitUse
		expectedMatchPairs.add(associate(addr(srcProg, "00412e90"), addr(destProg, "00412e70")));  // src:__setdefaultprecision dst: __setdefaultprecision

		expectedMatchPairs.add(associate(addr(srcProg, "00412fa0"), addr(destProg, "00412f80")));  // src:__onexit dst: __onexit -- similarity score < 0.5	

		expectedMatchPairs.add(associate(addr(srcProg, "004130d0"), addr(destProg, "004130b0")));  // src:_atexit dst: _atexit
		expectedMatchPairs.add(associate(addr(srcProg, "00413370"), addr(destProg, "00413350")));  // src:__IsNonwritableInCurrentImage dst: __IsNonwritableInCurrentImage
		expectedMatchPairs.add(associate(addr(srcProg, "004134e0"), addr(destProg, "004134c0")));  // src: FUN_004134e0 dst: FUN_004134c0
		expectedMatchPairs.add(associate(addr(srcProg, "00413520"), addr(destProg, "00413500")));  // src:_RTC_GetSrcLine dst: _RTC_GetSrcLine
		expectedMatchPairs.add(associate(addr(srcProg, "00413890"), addr(destProg, "00413870")));  // src:GetPdbDll dst: GetPdbDll

		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}

	/*
	 * Check that the scoring increases for a particular match as we add more references.
	 */
	@Test
	public void testCombinedReferenceCorrelator_compareScores() throws Exception {
		/*
		 * Define the testMatch for which we will test increasing scores.
		 */
		Address srcAddr = addr(srcProg, "004134e0");
		Address destAddr = addr(destProg, "004134c0");

		/*
		 * Create associated matches for the Reference correlator to work with.
		 */
		List<VTAssociationPair> associations = new ArrayList<>();
		/*		
		 * The defined testMatch references the following 3 items:
		 * 
		 *	Function	thunk_FUN_00411da0			thunk_FUN_00411d80		00411023	00411023	Implied Match
		 *	Data		DAT_00418000				DAT_00418000			00418000	00418000	Implied Match
		 *	Function	_except_handler4_common		_except_handler4_common	004111db	004111d6	Implied Match
		 * */
		/***********************************/
		/* Since the first reference is to a Thunk Function, we take the Thunked Function instead */
		associations.add(associate(addr(srcProg, "00411da0"), addr(destProg, "00411d80"),
			VTAssociationType.FUNCTION));

		// Create matchSet
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}

		runTestCorrelator(testCorrelator);
		VTMatchSet testMatchSet = getVTMatchSet(testCorrelator); //get the matches only from the correlator just run
		VTMatch testMatch1 = getMatch(testMatchSet, srcAddr, destAddr);

		/*
		 * Adding the 2nd reference increases the Confidence and Similarity Scores.
		 * The overall score will increase.
		 */
		associations.add(associate(addr(srcProg, "00418000"), addr(destProg, "00418000"),
			VTAssociationType.DATA));
		matchSet = createMatchSet(session, associations);
		matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}
		runTestCorrelator(testCorrelator);
		//get the matches only from the correlator just run
		testMatchSet = getVTMatchSet(testCorrelator);
		VTMatch testMatch2 = getMatch(testMatchSet, srcAddr, destAddr);

		assertTrue(hasHigherScore(testMatch2, testMatch1));

		/*
		 * Adding the 3rd and final reference increases the Confidence Score, but not the Similarity.
		 * The overall score will increase.
		 */
		associations.add(associate(addr(srcProg, "004111db"), addr(destProg, "004111d6"),
			VTAssociationType.FUNCTION));
		matchSet = createMatchSet(session, associations);
		matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}
		runTestCorrelator(testCorrelator);
		testMatchSet = getVTMatchSet(testCorrelator);
		VTMatch testMatch3 = getMatch(testMatchSet, srcAddr, destAddr);

		assertTrue(hasHigherScore(testMatch3, testMatch2));

		/*
		 * Confirm that every other match made from these three references scores lower than the correct one.
		 */
		matches = testMatchSet.getMatches();
		matches.remove(testMatch3);

		for (VTMatch match : matches) {
			assertTrue(hasHigherScore(testMatch3, match));
		}
	}

	/************************************************************************************
	 * Check that the scoring increases for a particular match as we add more references.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCombinedReferenceCorrelator_decreaseScores() throws Exception {
		/*
		 * Define the testMatch for which we will test increasing scores.
		 */
		Address srcAddr = addr(srcProg, "004134e0");
		Address destAddr = addr(destProg, "004134c0");
		VTMatchSet testMatchSet;

		/*
		 * Create associated matches for the Reference correlator to work with.
		 */
		List<VTAssociationPair> associations = new ArrayList<>();
		/*		
		 * The defined testMatch references the following 3 items:
		 * 
		 *	Function	thunk_FUN_00411da0			thunk_FUN_00411d80		00411023	00411023	Implied Match
		 *	Data		DAT_00418000				DAT_00418000			00418000	00418000	Implied Match
		 *	Function	_except_handler4_common		_except_handler4_common	004111db	004111d6	Implied Match
		 * */
		/***********************************/
		/* Since the first reference is to a Thunk Function, we take the Thunked Function instead */
		associations.add(associate(addr(srcProg, "00411da0"), addr(destProg, "00411d80")));

		// Create matchSet
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}

		runTestCorrelator(testCorrelator);
		testMatchSet = getVTMatchSet(testCorrelator); //get the matches only from the correlator just run
		VTMatch testMatch1 = getMatch(testMatchSet, srcAddr, destAddr);

		/*
		 * Adding the 2nd reference increases the Confidence and Similarity Scores.
		 * The overall score will increase.
		 */
		associations.add(associate(addr(srcProg, "00418000"), addr(destProg, "00418000"), DATA));
		matchSet = createMatchSet(session, associations);
		matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}
		runTestCorrelator(testCorrelator);
		//get the matches only from the correlator just run
		testMatchSet = getVTMatchSet(testCorrelator);
		VTMatch testMatch2 = getMatch(testMatchSet, srcAddr, destAddr);

		assertTrue(hasHigherScore(testMatch2, testMatch1));

		/*
		 * Adding an incorrect 3rd reference should decrease the Similarity.
		 */
		associations.add(associate(addr(srcProg, "004111db"), addr(destProg, "004115c0"),
			VTAssociationType.FUNCTION));
		matchSet = createMatchSet(session, associations);
		matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}
		runTestCorrelator(testCorrelator);
		testMatchSet = getVTMatchSet(testCorrelator);
		VTMatch testMatch3 = getMatch(testMatchSet, srcAddr, destAddr);

		assertTrue(!hasHigherScore(testMatch3, testMatch2));

		/*
		 * Confirm that every other match made from these three references scores lower than the correct one.
		 */
		matches = testMatchSet.getMatches();
		matches.remove(testMatch3);

		for (VTMatch match : matches) {
			assertTrue(hasHigherScore(testMatch3, match));
		}
	}

}
