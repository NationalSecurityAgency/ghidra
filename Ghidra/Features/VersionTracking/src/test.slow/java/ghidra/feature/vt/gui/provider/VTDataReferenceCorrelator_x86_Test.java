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

public class VTDataReferenceCorrelator_x86_Test extends AbstractVTCorrelatorTest {

	private String testCorrelator = "Data Reference Match";

	public VTDataReferenceCorrelator_x86_Test() {
		super("VersionTracking/WallaceSrc.gzf", "VersionTracking/WallaceVersion2.gzf");
	}

	/*
	 * Specify 3 known data matches referenced by the "print" functions, then run the Data Reference 
	 * Correlator and test that only the print functions match
	 */
	@Test
	public void testDataReferenceCorrelator_onlyprintDataMatches() throws Exception {

		/*
		 * First create associated matches for the Reference correlator to work with.
		 */
		List<VTAssociationPair> associations = new ArrayList<>();

		//s_%s_%s_deployed_on_%s__00416830
		associations.add(new VTAssociationPair(addr(srcProg, "00416830"),
			addr(destProg, "00416830"), VTAssociationType.DATA));
		//s_anyone_0041684c
		associations.add(new VTAssociationPair(addr(srcProg, "0041684c"),
			addr(destProg, "0041684c"), VTAssociationType.DATA));
		//s_is_not_00416858
		associations.add(new VTAssociationPair(addr(srcProg, "00416858"),
			addr(destProg, "00416858"), VTAssociationType.DATA));

		// Create matches
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		final Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}

		//Run the Data Reference Correlator
		runTestCorrelator(testCorrelator);

		//get the matches only from the correlator just run
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();
		expectedMatchPairs.add(associate(addr(srcProg, "004115d0"), addr(destProg, "004115c0"))); //src: print

		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}

	/*
	 * Run the Exact Data Match correlator and accept all matches, 
	 * then run the Data Reference Correlator and test that the expected matches match and
	 * that nothing else matches
	 */
	@Test
	public void testDataReferenceCorrelator_allDataMatches() throws Exception {

		//Run the Exact Data Correlator
		runTestCorrelator("Exact Data Match");

		// apply all exact data matches
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet ms : matchSets) {
			ApplyMatchTask task = new ApplyMatchTask(controller, (List<VTMatch>) ms.getMatches());
			runTask(task);
		}

		// run the correlator that we are testing with lowered similarity threshold
		runTestReferenceCorrelatorWithOptions(testCorrelator, 1.0,
			VTAbstractReferenceProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT, 0.1, true);

		//get the matches only from the correlator just run
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();

		expectedMatchPairs.add(associate(addr(srcProg, "004118f0"), addr(destProg, "004118c0")));  // src:deployGadget dst: FUN_004118c0
		expectedMatchPairs.add(associate(addr(srcProg, "004115d0"), addr(destProg, "004115c0")));  // src:print dst: print
		expectedMatchPairs.add(associate(addr(srcProg, "00411700"), addr(destProg, "004116f0")));  // src:addPeople dst: addPeople
		expectedMatchPairs.add(associate(addr(srcProg, "00411f00"), addr(destProg, "00411ee0")));  // src:___tmainCRTStartup dst: ___tmainCRTStartup -- similarity score < 0.5
		expectedMatchPairs.add(associate(addr(srcProg, "004122b0"), addr(destProg, "00412290")));  // src:__RTC_GetErrDesc dst: __RTC_GetErrDesc
		expectedMatchPairs.add(associate(addr(srcProg, "00412380"), addr(destProg, "00412360")));  // src:_RTC_Failure dst: _RTC_Failure
		expectedMatchPairs.add(associate(addr(srcProg, "004123f0"), addr(destProg, "004123d0")));  // src:failwithmessage dst: failwithmessage
		expectedMatchPairs.add(associate(addr(srcProg, "00412810"), addr(destProg, "004127f0")));  // src:_RTC_StackFailure dst: _RTC_StackFailure
		expectedMatchPairs.add(associate(addr(srcProg, "00412950"), addr(destProg, "00412930")));  // src:_RTC_AllocaFailure dst: _RTC_AllocaFailure
		expectedMatchPairs.add(associate(addr(srcProg, "00412ad0"), addr(destProg, "00412ab0")));  // src:_getMemBlockDataString dst: _getMemBlockDataString
		expectedMatchPairs.add(associate(addr(srcProg, "00412b60"), addr(destProg, "00412b40")));  // src:__RTC_UninitUse dst: __RTC_UninitUse
		expectedMatchPairs.add(associate(addr(srcProg, "00412e90"), addr(destProg, "00412e70")));  // src:__setdefaultprecision dst: __setdefaultprecision
		expectedMatchPairs.add(associate(addr(srcProg, "00413520"), addr(destProg, "00413500")));  // src:_RTC_GetSrcLine dst: _RTC_GetSrcLine
		expectedMatchPairs.add(associate(addr(srcProg, "00413890"), addr(destProg, "00413870")));  // src:GetPdbDll dst: GetPdbDll

		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}
	/*
	 * End Tests
	 *******************************************************************************/

}
