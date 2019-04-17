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

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.gui.task.ApplyMatchTask;

public class VTFunctionReferenceCorrelator_ELF_Test extends AbstractVTCorrelatorTest {

	private String testCorrelator = "Function Reference Match";

	public VTFunctionReferenceCorrelator_ELF_Test() {
		super("VersionTracking/helloWorld64.gzf", "VersionTracking/helloWorld32.gzf");
	}

	/* *******************************************************************************
	 * Begin Tests
	 */
	/************************************************************************************
	 * Specify only function matches referenced by single function, then run the Function 
	 * Reference Correlator and make sure it matches only on functions that have those function references
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFunctionReferenceCorrelator_onlyBobFunctionMatches() throws Exception {

		/*
		 * First create associated External Function matches for the Reference correlator to work with.
		 * Such matches could be established by an Exact Symbol Name match
		 */
		List<VTAssociationPair> associations = new ArrayList<>();

		// <EXTERNAL>::sprintf
		associations.add(
			associate(externalAddrFor(srcProg, "sprintf"), externalAddrFor(destProg, "sprintf")));
		// <EXTERNAL>::printf
		associations.add(
			associate(externalAddrFor(srcProg, "printf"), externalAddrFor(destProg, "printf")));
		// <EXTERNAL>::fprintf function
		associations.add(
			associate(externalAddrFor(srcProg, "fprintf"), externalAddrFor(destProg, "fprintf")));

		// Create matches
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}

		//Run the Function Reference Correlator
		runTestCorrelator(testCorrelator);

		//get matches from only the run correlator
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatches = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatches = new HashSet<>();
		expectedMatches.add(associate(addr(srcProg, "0040063e"), addr(destProg, "080484ca"))); //src: bob dest: bob

		//Test that all the matches are right and there are no extra
		assertMatchPairs(expectedMatches, testMatches);

	}

	/************************************************************************************
	 * Run the Exact Function Match correlator and accept all matches, 
	 * then run the Function Reference Correlator and test that only expected matches are found
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFunctionReferenceCorrelator_allFunctionMatches() throws Exception {

		//Run Exact Symbol Name Correlator (because no exact instruction matches)
		String exactSymbolNameCorrelator = "Exact Symbol Name Match";
		runTestCorrelator(exactSymbolNameCorrelator);

		// apply all matches with exact symbol names - assuming it won't matter that data matches will be applied, too
		List<VTMatchSet> exactMatchSets = session.getMatchSets();
		for (VTMatchSet ms : exactMatchSets) {
			String corrName = ms.getProgramCorrelatorInfo().getName();
			if (corrName == exactSymbolNameCorrelator) {
				ApplyMatchTask task =
					new ApplyMatchTask(controller, (List<VTMatch>) ms.getMatches());
				runTask(task);
			}
		}

		runTestCorrelator(testCorrelator);

		//get matches from only the run correlator
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Construct the set of expected matches based on function matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();

		expectedMatchPairs.add(associate(addr(srcProg, "00400938"), addr(destProg, "0804874c")));  // src:_fini dst: _fini
		expectedMatchPairs.add(associate(addr(srcProg, "00400870"), addr(destProg, "080486c0")));  // src:__libc_csu_init dst: __libc_csu_init
		expectedMatchPairs.add(associate(addr(srcProg, "004004b0"), addr(destProg, "08048334")));  // src:_init dst: _init
		expectedMatchPairs.add(associate(addr(srcProg, "0040079c"), addr(destProg, "080485f3")));  // src:main dst: main
		expectedMatchPairs.add(associate(addr(srcProg, "00400540"), addr(destProg, "080483f0")));  // src:_start dst: _start
		expectedMatchPairs.add(associate(addr(srcProg, "0040063e"), addr(destProg, "080484ca")));  // src:bob dst: bob (based upon accepted external function symbol matches)

		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}

}
