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

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.task.ApplyMatchTask;

public class VTDataReferenceCorrelator_ELF_Test extends AbstractVTCorrelatorTest {

	private String testCorrelator = "Data Reference Match";

	public VTDataReferenceCorrelator_ELF_Test() {
		super("VersionTracking/helloWorld64.gzf", "VersionTracking/helloWorld32.gzf");
	}

	/* *******************************************************************************
	 * Begin Tests
	 */

	/************************************************************************************
	 * Specify only known data matches referenced by the "bob" functions, then run the Data Reference 
	 * Correlator and test that only the bob functions match
	 * 
	 * @throws Exception
	 */
	@Test
	public void testDataReferenceCorrelator_onlybobDataMatches() throws Exception {

		/*
		 * First create associated matches for the Reference correlator to work with.
		 */
		List<VTAssociationPair> associations = new ArrayList<>();
		//s_a=%d,_b=%f,_c=%c_... strings
		associations.add(associate(addr(srcProg, "00400958"), addr(destProg, "08048778"),
			VTAssociationType.DATA));
		//s_total... string
		associations.add(associate(addr(srcProg, "0040096a"), addr(destProg, "0804878a"),
			VTAssociationType.DATA));

		//labeled "total" data - undefined4
		associations.add(associate(addr(srcProg, "00600d34"), addr(destProg, "0804999c"),
			VTAssociationType.DATA));
		//labeled "average" data - undefined4
		associations.add(associate(addr(srcProg, "00600d38"), addr(destProg, "080499a0"),
			VTAssociationType.DATA));
		// "stderr" data
		associations.add(associate(addr(srcProg, "00600d40"), addr(destProg, "080499a4"),
			VTAssociationType.DATA));

		// Create matches
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}

		//Run the Combined Reference Correlator
		runTestCorrelator(testCorrelator);

		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs returned from the correlator
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatches = new HashSet<>();
		expectedMatches.add(associate(addr(srcProg, "0040063e"), addr(destProg, "080484ca"))); //src: bob dst: bob

		//Test that all the matches are right and there are no extra/missing
		assertMatchPairs(expectedMatches, testMatchPairs);

	}

	/************************************************************************************
	 * Run the Exact Data Match correlator and accept all matches, 
	 * then run the Data Reference Correlator and test that only the expected matches are found
	 * 
	 * @throws Exception
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

		// run the correlator that we are testing
		runTestCorrelator(testCorrelator);

		//get the matches only from the correlator just run
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();

		expectedMatchPairs.add(associate(addr(srcProg, "0040063e"), addr(destProg, "080484ca")));  // src: bob dst: bob 
		expectedMatchPairs.add(associate(addr(srcProg, "0040079c"), addr(destProg, "080485f3")));  // src: main dst: main
		expectedMatchPairs.add(associate(addr(srcProg, "00400764"), addr(destProg, "080485b7")));  // src: goodbye dst: goodbye
		expectedMatchPairs.add(associate(addr(srcProg, "00400738"), addr(destProg, "08048581")));  // src: hello dst: hello

		//test that all the matches are right and there are no extra
		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}

	/*
	 * End Tests
	 *******************************************************************************/
}
