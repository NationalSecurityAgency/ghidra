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
import static ghidra.feature.vt.api.main.VTAssociationType.FUNCTION;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.*;

import org.junit.Assert;
import org.junit.Test;

import ghidra.feature.vt.api.correlator.program.VTAbstractReferenceProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.gui.task.AcceptMatchTask;
import ghidra.program.model.address.Address;

public class VTCombinedFunctionDataReferenceCorrelator_ELF_Test extends AbstractVTCorrelatorTest {

	private String testCorrelator = "Combined Function and Data Reference Match";

	public VTCombinedFunctionDataReferenceCorrelator_ELF_Test() {
		super("VersionTracking/helloWorld64.gzf", "VersionTracking/helloWorld32.gzf");
	}

	/* *******************************************************************************
	 * Begin Tests
	 */
	/************************************************************************************
	 * Specify only function matches, then run the Combined Function/Data Reference Correlator
	 * and make sure it does not match on function that has both data and function references
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCorrelatorUsingOnlyFunctionMatches() throws Exception {

		/*
		 * First create associated matches for the Reference correlator to work with.
		 */
		List<VTAssociationPair> associations = new ArrayList<>();

		//.plt::sprintf
		associations.add(
			associate(addr(srcProg, "00400508"), addr(destProg, "08048374"), FUNCTION));
		//.plt::printf
		associations.add(
			associate(addr(srcProg, "004004d8"), addr(destProg, "080483a4"), FUNCTION));
		// .plt::fprintf function
		associations.add(
			associate(addr(srcProg, "00400528"), addr(destProg, "080483b4"), FUNCTION));

		// Create matches
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		final Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}

		//Run the Combined Reference Correlator
		// bob is found with a fairly low similarity score (0.554) when all three functions are matched
		runTestReferenceCorrelatorWithOptions(testCorrelator, 1.0,
			VTAbstractReferenceProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT, 0.6, true);

		/* Check that the match set was created and that there are no matches 
		 - nothing should match with just the above listed function matches
		 */
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);
		assertEquals(vtMatchSet.getMatchCount(), 0);

	}

	/************************************************************************************
	 * Specify only data matches, then run the Combined Function/Data Reference Correlator
	 * and make sure it finds but scores lower than the same function found by the Data
	 * Reference Correlator.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCorrelatorUsingSelectedDataMatches() throws Exception {

		/*
		 * First create associated matches for the Reference correlator to work with.
		 */
		List<VTAssociationPair> associations = new ArrayList<>();
		//s_a=%d,_b=%f,_c=%c_... strings
		associations.add(associate(addr(srcProg, "00400958"), addr(destProg, "08048778"), DATA));
		//labeled "total" data - undefined4
		associations.add(associate(addr(srcProg, "00600d34"), addr(destProg, "0804999c"), DATA));
		//labeled "average" data - undefined4
		associations.add(associate(addr(srcProg, "00600d38"), addr(destProg, "080499a0"), DATA));
		//s_total... string
		associations.add(associate(addr(srcProg, "0040096a"), addr(destProg, "080499a0"), DATA));
		// "stderr" data
		associations.add(associate(addr(srcProg, "00600d40"), addr(destProg, "080499a4"), DATA));

		// Create matches
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		final Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			applyMatch(match);
		}

		//Run the Combined Reference Correlator
		runTestCorrelator(testCorrelator);

		VTMatchSet testMatchSet = getVTMatchSet(testCorrelator);
		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(testMatchSet);

		//Check that there is only one match

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();
		Address srcAddr = addr(srcProg, "0040063e");
		Address destAddr = addr(destProg, "080484ca");
		expectedMatchPairs.add(associate(srcAddr, destAddr)); //src: bob dst: bob

		//This tests that all the expected matches are right and there are no extra
		assertMatchPairs(expectedMatchPairs, testMatchPairs);

		//Run the Data Reference Correlator
		runTestCorrelator("Data Reference Match");
		VTMatchSet dataMatchSet = getVTMatchSet("Data Reference Match");
		assertTrue(hasHigherScore(getMatch(dataMatchSet, srcAddr, destAddr),
			getMatch(testMatchSet, srcAddr, destAddr)));

	}

	/************************************************************************************
	 * Specify both function and data matches that are references in the bob function (no other
	 * has all of the same references), then run the Combined Function/Data Reference Correlator
	 * and make sure it only matches on the bob functions
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCombinedReferenceCorrelator_onlyDataAndFunctionsMatches() throws Exception {

		/*
		 * First create associated matches for the Reference correlator to work with.
		 */
		List<VTAssociationPair> associations = new ArrayList<>();

		//s_a=%d,_b=%f,_c=%c_... strings
		associations.add(associate(addr(srcProg, "00400958"), addr(destProg, "08048778"), DATA));
		//.plt::sprintf
		associations.add(
			associate(addr(srcProg, "00400508"), addr(destProg, "08048374"), FUNCTION));
		//.plt::printf
		associations.add(
			associate(addr(srcProg, "004004d8"), addr(destProg, "080483a4"), FUNCTION));
		//labeled "total" data - undefined4
		associations.add(associate(addr(srcProg, "00600d34"), addr(destProg, "0804999c"), DATA));
		//labeled "average" data - undefined4
		associations.add(associate(addr(srcProg, "00600d38"), addr(destProg, "080499a0"), DATA));
		//s_total... string
		associations.add(associate(addr(srcProg, "0040096a"), addr(destProg, "080499a0"), DATA));
		// "stderr" data
		associations.add(associate(addr(srcProg, "00600d40"), addr(destProg, "080499a4"), DATA));
		// .plt::fprintf function
		associations.add(
			associate(addr(srcProg, "00400528"), addr(destProg, "080483b4"), FUNCTION));

		// Create matches
		VTMatchSet matchSet = createMatchSet(session, associations);

		/* apply the matches created above */
		final Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			acceptMatch(match);
		}

		//Run the Combined Reference Correlator
		runTestCorrelator(testCorrelator);
		VTMatchSet vtMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, vtMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(vtMatchSet);

		// Make the set of expected matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();
		expectedMatchPairs.add(associate(addr(srcProg, "0040063e"), addr(destProg, "080484ca"))); //src: bob dst: bob

		//This tests that all the expected matches are right and there are no extra
		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}

	/************************************************************************************
	 * Run the Exact Symbol Name correlator and accept all function matches, 
	 * then run the Exact Data Match Correlator and accept all matches
	 * then accept manually created matches
	 * then run the Combined Data and Function reference correlator 
	 * and test that only the expected matches are found
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFunctionReferenceCorrelator_allFunctionMatches() throws Exception {

		//Run Exact Symbol Name Correlator (because no exact instruction matches)
		String exactSymbolNameCorrelator = "Exact Symbol Name Match";
		runTestCorrelator(exactSymbolNameCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null,
			getVTMatchSet(exactSymbolNameCorrelator));

		//Run the Exact Data Correlator		
		String exactDataCorrelator = "Exact Data Match";
		runTestCorrelator(exactDataCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null,
			getVTMatchSet(exactDataCorrelator));

		// apply all matches
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet ms : matchSets) {
			AcceptMatchTask task = new AcceptMatchTask(controller, (List<VTMatch>) ms.getMatches());
			runTask(task);
		}

		// Create Manual Dummy matches
		List<VTAssociationPair> associations = new ArrayList<>();
		//bob -	bob
		associations.add(
			associate(addr(srcProg, "0040063e"), addr(destProg, "080484ca"), FUNCTION));
		//frame_dummy	frame_dummy
		associations.add(
			associate(addr(srcProg, "00400600"), addr(destProg, "08048480"), FUNCTION));
		//__libc_csu_fini	__libc_csu_fini
		associations.add(
			associate(addr(srcProg, "00400860"), addr(destProg, "080486b0"), FUNCTION));
		//_init	_init
		associations.add(
			associate(addr(srcProg, "004004b0"), addr(destProg, "08048334"), FUNCTION));

		//__do_global_ctors_aux	__do_global_ctors_aux
		associations.add(
			associate(addr(srcProg, "00400900"), addr(destProg, "08048720"), FUNCTION));
		//goodbye	goodbye
		associations.add(
			associate(addr(srcProg, "00400764"), addr(destProg, "080485b7"), FUNCTION));
		//_start	_start
		associations.add(
			associate(addr(srcProg, "00400540"), addr(destProg, "080483f0"), FUNCTION));
		//main	main
		associations.add(
			associate(addr(srcProg, "0040079c"), addr(destProg, "080485f3"), FUNCTION));
		//__do_global_dtors_aux	__do_global_dtors_aux
		associations.add(
			associate(addr(srcProg, "00400590"), addr(destProg, "08048420"), FUNCTION));
		//hello	hello
		associations.add(
			associate(addr(srcProg, "00400738"), addr(destProg, "08048581"), FUNCTION));
		//__libc_csu_init	__libc_csu_init
		associations.add(
			associate(addr(srcProg, "00400870"), addr(destProg, "080486c0"), FUNCTION));
		//mypow	mypow
		associations.add(
			associate(addr(srcProg, "00400624"), addr(destProg, "080484a4"), FUNCTION));
		//_fini	_fini
		associations.add(
			associate(addr(srcProg, "00400938"), addr(destProg, "0804874c"), FUNCTION));

		/* apply the manual matches created above */
		final Collection<VTMatch> funMatches = createMatchSet(session, associations).getMatches();
		for (VTMatch match : funMatches) {

			acceptMatch(match);
		}

		//run the Combined Data and Function reference correlator		
		runTestCorrelatorWithDefaultOptions(testCorrelator);

		VTMatchSet testMatchSet = getVTMatchSet(testCorrelator);
		Assert.assertNotEquals("vtMatchSet does not exist", null, testMatchSet);

		//make a set of test match pairs
		Set<VTAssociationPair> testMatchPairs = getMatchAddressPairs(testMatchSet);

		// Construct the set of expected matches based on function matches
		Set<VTAssociationPair> expectedMatchPairs = new HashSet<>();
		expectedMatchPairs.add(associate(addr(srcProg, "00400540"), addr(destProg, "080483f0")));  // src:_start 			dst: _start
		expectedMatchPairs.add(associate(addr(srcProg, "00400938"), addr(destProg, "0804874c")));  // src:_fini 			dst: _fini
		expectedMatchPairs.add(associate(addr(srcProg, "004004b0"), addr(destProg, "08048334")));  // src:_init 			dst: _init
		expectedMatchPairs.add(associate(addr(srcProg, "0040063e"), addr(destProg, "080484ca")));  // src: bob 				dst: bob
		expectedMatchPairs.add(associate(addr(srcProg, "00400738"), addr(destProg, "08048581")));  // src: hello 			dst: hello
		expectedMatchPairs.add(associate(addr(srcProg, "00400764"), addr(destProg, "080485b7")));  // src: goodbye 			dst: goodbye
		expectedMatchPairs.add(associate(addr(srcProg, "0040079c"), addr(destProg, "080485f3")));  // src: main 			dst: main
		expectedMatchPairs.add(associate(addr(srcProg, "00400870"), addr(destProg, "080486c0")));  // src:__libc_csu_init 	dst: __libc_csu_init

		// New functions found with updated scoring method
		expectedMatchPairs.add(associate(addr(srcProg, "00400590"), addr(destProg, "08048420")));  // src: __do_global_dtors_aux		dst:__do_global_dtors_aux
		expectedMatchPairs.add(associate(addr(srcProg, "00400900"), addr(destProg, "08048720")));  // src: __do_global_ctors_aux	 	dst:__do_global_ctors_aux
		expectedMatchPairs.add(associate(addr(srcProg, "00400600"), addr(destProg, "08048480")));  // src: frame_dummy		dst: frame_dummy

		//This tests that all the expected matches are right and there are no extra
		assertMatchPairs(expectedMatchPairs, testMatchPairs);

	}
}
