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

import java.util.*;

import org.junit.Assert;
import org.junit.Test;

import ghidra.feature.vt.api.correlator.program.VTAbstractReferenceProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.task.ApplyMatchTask;

public class VTFunctionReferenceCorrelator_x86_Test extends AbstractVTCorrelatorTest {

	private String testCorrelator = "Function Reference Match";

	public VTFunctionReferenceCorrelator_x86_Test() {
		super("VersionTracking/WallaceSrc.gzf", "VersionTracking/WallaceVersion2.gzf");
	}

	/*
	 * Specify 3 known matches, then run the testCorrelator
	 * and test that only one match
	 */
	@Test
	public void testFunctionReferenceCorrelator_givenSomeExternalMatches() throws Exception {

		/*
		 * First create associated matches for the Reference correlator to work with.
		 */
		List<VTAssociationPair> associations = new ArrayList<>();

		//_XcptFilter
		associations.add(associate(addr(srcProg, "4110e6"), addr(destProg, "4110e6")));
		//_initterm
		associations.add(associate(addr(srcProg, "4111f9"), addr(destProg, "4111f4")));

		// Create matches
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		ApplyMatchTask task = new ApplyMatchTask(controller, (List<VTMatch>) matchSet.getMatches());
		runTask(task);

		//Run the test Correlator
		runTestCorrelator(testCorrelator);

		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();
		expectedMatchPairs.add(associate(addr(srcProg, "00411bb0"), addr(destProg, "00411b90"))); //src: @_RTC_CheckStackVars@8
		expectedMatchPairs.add(associate(addr(srcProg, "00411c70"), addr(destProg, "00411c50"))); //src: @_RTC_CheckStackVars2@12

		//This tests that all the matches are right and there are no extra
		assertMatchPairs(expectedMatchPairs, testMatchPairs);
	}

	/*
	 * Run the Exact Function Instructions Match correlator and accept all matches, 
	 * then run the Function Reference correlator and make sure only the expected matches match
	 */
	@Test
	public void testFunctionReferenceCorrelator_givenAllExactFunctionMatches() throws Exception {

		//Run the Exact Function Correlator
		String exactMatchCorrelator = "Exact Function Instructions Match";
		runTestCorrelator(exactMatchCorrelator);

		// apply all exact matches
		List<VTMatchSet> exactMatchSets = session.getMatchSets();
		for (VTMatchSet ms : exactMatchSets) {
			if (ms.getProgramCorrelatorInfo().getName() == exactMatchCorrelator) {
				ApplyMatchTask task =
					new ApplyMatchTask(controller, (List<VTMatch>) ms.getMatches());
				runTask(task);
			}
		}

		//Run the Function Reference Correlator with a slightly lowered score threshold to catch all the expected matches
		runTestReferenceCorrelatorWithOptions(testCorrelator, 1.0,
			VTAbstractReferenceProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT, 0.4, true);

		//get the matches only from the correlator just run
		VTMatchSet testMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, testMatchSet);

		//make a set of test match pairs from correlator results
		Set<VTAssociationPair> testMatchPairs = new HashSet<>();
		for (VTMatch vtMatch : testMatchSet.getMatches()) {
			if (vtMatch.getAssociation().getStatus() != VTAssociationStatus.BLOCKED) {
				testMatchPairs.add(toPair(vtMatch));
			}
		}

		/* Make the set of expected matches
		 * 
		 * NOTE 1: The commented out matches score lower than the threshold for the new scoring mechanism
		 * NOTE 2: The print function is not matched here because it scores identically to other possible matches when only considering function references:
		 * 		Gadget::print -- Gadget::print similarity:    0.7022663247717663
		 * 		initializePeople -- Gadget::print similarity: 0.7022663247717663
		 * 		Call_strncpy_s -- Gadget::print similarity:   0.7022663247717663		 */

		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();
		expectedMatchPairs.add(associate(addr(srcProg, "00411700"), addr(destProg, "004116f0")));  // src:addPeople dst: addPeople
		expectedMatchPairs.add(associate(addr(srcProg, "00411860"), addr(destProg, "00411830")));  // src:addPerson dst: addPerson
		expectedMatchPairs.add(associate(addr(srcProg, "004118f0"), addr(destProg, "004118c0")));  // src:deployGadget dst: FUN_004118c0
		expectedMatchPairs.add(associate(addr(srcProg, "00411a30"), addr(destProg, "00411a10")));  // src:main dst: main

		expectedMatchPairs.add(associate(addr(srcProg, "00411b80"), addr(destProg, "00411b60")));  // src:__RTC_CheckEsp dst: __RTC_CheckEsp
		expectedMatchPairs.add(associate(addr(srcProg, "00411bb0"), addr(destProg, "00411b90")));  // src:@_RTC_CheckStackVars@8 dst: @_RTC_CheckStackVars@8
		expectedMatchPairs.add(associate(addr(srcProg, "00411c70"), addr(destProg, "00411c50")));  // src:@_RTC_CheckStackVars2@12 dst: @_RTC_CheckStackVars2@12 
		expectedMatchPairs.add(associate(addr(srcProg, "00411dc0"), addr(destProg, "00411da0")));  // src:FUN_00411dc0 dst: FUN_00411da0		
		expectedMatchPairs.add(associate(addr(srcProg, "00411e70"), addr(destProg, "00411e50")));  // src:FUN_00411e70 dst: FUN_00411e50
		expectedMatchPairs.add(associate(addr(srcProg, "00411ee0"), addr(destProg, "00411ec0")));  // src:_mainCRTStartup dst: _mainCRTStartup		

		expectedMatchPairs.add(associate(addr(srcProg, "00411f00"), addr(destProg, "00411ee0")));  // src:___tmainCRTStartup dst: ___tmainCRTStartup
		expectedMatchPairs.add(associate(addr(srcProg, "00412380"), addr(destProg, "00412360")));  // src:_RTC_Failure dst: _RTC_Failure		
		expectedMatchPairs.add(associate(addr(srcProg, "004123f0"), addr(destProg, "004123d0")));  // src:failwithmessage dst: failwithmessage
		expectedMatchPairs.add(associate(addr(srcProg, "00412950"), addr(destProg, "00412930")));  // src:_RTC_AllocaFailure dst: _RTC_AllocaFailure

		expectedMatchPairs.add(associate(addr(srcProg, "00412e90"), addr(destProg, "00412e70")));  // src:__setdefaultprecision dst: __setdefaultprecision
		expectedMatchPairs.add(associate(addr(srcProg, "00412fa0"), addr(destProg, "00412f80")));  // src:__onexit dst: __onexit <-- makes several external calls, which increases the number non-matched function calls and decreasing the score appropriately

		expectedMatchPairs.add(associate(addr(srcProg, "004130d0"), addr(destProg, "004130b0")));  // src:_atexit dst: _atexit
		expectedMatchPairs.add(associate(addr(srcProg, "00413370"), addr(destProg, "00413350")));  // src:__IsNonwritableInCurrentImage dst: __IsNonwritableInCurrentImage
		expectedMatchPairs.add(associate(addr(srcProg, "004134e0"), addr(destProg, "004134c0")));
		expectedMatchPairs.add(associate(addr(srcProg, "00413520"), addr(destProg, "00413500")));  // src:_RTC_GetSrcLine dst: _RTC_GetSrcLine

		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}

	/*
	 * Run the Exact Function Instructions Match correlator and accept all matches, 
	 * then run the Function Reference correlator and make sure only the expected matches match
	 */
	@Test
	public void testFunctionReferenceCorrelator_givenAllExactFunctionMatchesUnrefined()
			throws Exception {

		//Run the Exact Function Correlator
		String exactMatchCorrelator = "Exact Function Instructions Match";
		runTestCorrelator(exactMatchCorrelator);

		// apply all exact matches
		List<VTMatchSet> exactMatchSets = session.getMatchSets();
		for (VTMatchSet ms : exactMatchSets) {
			if (ms.getProgramCorrelatorInfo().getName() == exactMatchCorrelator) {
				ApplyMatchTask task =
					new ApplyMatchTask(controller, (List<VTMatch>) ms.getMatches());
				runTask(task);
			}
		}

		//Run the Function Reference Correlator
		runTestReferenceCorrelatorWithOptions(testCorrelator, 1.0,
			VTAbstractReferenceProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT, 0.4, false);

		//get the matches only from the correlator just run
		VTMatchSet testMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, testMatchSet);

		//make a set of test match pairs from correlator results
		Set<VTAssociationPair> testMatchPairs = new HashSet<>();
		for (VTMatch vtMatch : testMatchSet.getMatches()) {
			if (vtMatch.getAssociation().getStatus() != VTAssociationStatus.BLOCKED) {
				testMatchPairs.add(toPair(vtMatch));
			}
		}

		/* Make the set of expected matches
		 * 
		 * NOTE: By removing the refine step we see functions that otherwise have conflicting scores.  
		 */

		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();
		expectedMatchPairs.add(associate(addr(srcProg, "00411700"), addr(destProg, "004116f0")));  // src:addPeople dst: addPeople
		expectedMatchPairs.add(associate(addr(srcProg, "00411860"), addr(destProg, "00411830")));  // src:addPerson dst: addPerson
		expectedMatchPairs.add(associate(addr(srcProg, "004118f0"), addr(destProg, "004118c0")));  // src:deployGadget dst: FUN_004118c0
		expectedMatchPairs.add(associate(addr(srcProg, "00411a30"), addr(destProg, "00411a10")));  // src:main dst: main

		expectedMatchPairs.add(associate(addr(srcProg, "00411b80"), addr(destProg, "00411b60")));  // src:__RTC_CheckEsp dst: __RTC_CheckEsp
		expectedMatchPairs.add(associate(addr(srcProg, "00411bb0"), addr(destProg, "00411b90")));  // src:@_RTC_CheckStackVars@8 dst: @_RTC_CheckStackVars@8
		expectedMatchPairs.add(associate(addr(srcProg, "00411c70"), addr(destProg, "00411c50")));  // src:@_RTC_CheckStackVars2@12 dst: @_RTC_CheckStackVars2@12 
		expectedMatchPairs.add(associate(addr(srcProg, "00411dc0"), addr(destProg, "00411da0")));  // src:FUN_00411dc0 dst: FUN_00411da0		
		expectedMatchPairs.add(associate(addr(srcProg, "00411e70"), addr(destProg, "00411e50")));  // src:FUN_00411e70 dst: FUN_00411e50
		expectedMatchPairs.add(associate(addr(srcProg, "00411ee0"), addr(destProg, "00411ec0")));  // src:_mainCRTStartup dst: _mainCRTStartup		

		expectedMatchPairs.add(associate(addr(srcProg, "00411f00"), addr(destProg, "00411ee0")));  // src:___tmainCRTStartup dst: ___tmainCRTStartup
		expectedMatchPairs.add(associate(addr(srcProg, "00412380"), addr(destProg, "00412360")));  // src:_RTC_Failure dst: _RTC_Failure		
		expectedMatchPairs.add(associate(addr(srcProg, "004123f0"), addr(destProg, "004123d0")));  // src:failwithmessage dst: failwithmessage
		expectedMatchPairs.add(associate(addr(srcProg, "00412950"), addr(destProg, "00412930")));  // src:_RTC_AllocaFailure dst: _RTC_AllocaFailure

		expectedMatchPairs.add(associate(addr(srcProg, "00412e90"), addr(destProg, "00412e70")));  // src:__setdefaultprecision dst: __setdefaultprecision
		expectedMatchPairs.add(associate(addr(srcProg, "00412fa0"), addr(destProg, "00412f80")));  // src:__onexit dst: __onexit <-- makes several external calls, which increases the number non-matched function calls and decreasing the score appropriately

		expectedMatchPairs.add(associate(addr(srcProg, "004130d0"), addr(destProg, "004130b0")));  // src:_atexit dst: _atexit
		expectedMatchPairs.add(associate(addr(srcProg, "00413370"), addr(destProg, "00413350")));  // src:__IsNonwritableInCurrentImage dst: __IsNonwritableInCurrentImage
		expectedMatchPairs.add(associate(addr(srcProg, "004134e0"), addr(destProg, "004134c0")));
		expectedMatchPairs.add(associate(addr(srcProg, "00413520"), addr(destProg, "00413500")));  // src:_RTC_GetSrcLine dst: _RTC_GetSrcLine

		// Unrefined Correlations
		expectedMatchPairs.add(associate(addr(srcProg, "004115d0"), addr(destProg, "004115c0")));  // src: print 			dst: print
		expectedMatchPairs.add(associate(addr(srcProg, "00411ab0"), addr(destProg, "00411a90")));  // src: Call_strncpy_s 	dst: Call_strncpy_s
		expectedMatchPairs.add(associate(addr(srcProg, "00412b60"), addr(destProg, "00412b40")));  // src: __RTC_UninitUse 	dst: __RTC_UninitUse
		expectedMatchPairs.add(associate(addr(srcProg, "00412810"), addr(destProg, "004127f0")));  // src: _RTC_StackFailure dst: _RTC_StackFailure

		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}

}
