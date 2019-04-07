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
package ghidra.feature.vt.api;

import static ghidra.feature.vt.db.VTTestUtils.addr;
import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.db.VTTestUtils;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.actions.AutoVersionTrackingCommand;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class VTAutoVersionTrackingTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String TEST_SOURCE_PROGRAM_NAME = "VersionTracking/WallaceSrc";
	private static final String TEST_DESTINATION_PROGRAM_NAME = "VersionTracking/WallaceVersion2";

	private VTTestEnv env;
	private VTController controller;
	private ProgramDB sourceProgram;
	private ProgramDB destinationProgram;
	private VTSessionDB session;

	public VTAutoVersionTrackingTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);
		env = new VTTestEnv();

	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	/*
	 * This tests auto version tracking with score/confidence values that will pretty much ensure
	 * that all matches are good matches.
	 */
	@Test
	public void testRunAutoVT_moreCautious() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// Score 1.0 and confidence 10.0 (log10 confidence 2.0) and up
		boolean success = runAutoVTCommand(1.0, 10.0);
		assertTrue("Auto Version Tracking Command failed to run", success);

		// verify that the default options are what we expect
		// if this assert fails then the follow-on tests will probably fail 
		assertCorrectOptionValues(session, "1.0", "10.0");

		// verify that given the above verified conditions the 
		// exact unique correlators (which have their own tests to verify which matches are
		// correct) return the expected number of possible matches and accepted matches
		// since they are exact and unique and this number is already known based on other tests
		// this is just verifying that what we expect to happen is happening for debug purposes 
		// in case something is changed in the future that would alter these numbers.
		// We need to know that these are as expected before testing the non-exact/unique correlator
		// results that depend on these answers. 
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Symbol Name Match", 203, 203);
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Data Match", 125, 125);
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Function Bytes Match", 18, 18);
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Function Instructions Match",
			47, 47);
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Function Mnemonics Match", 44,
			44);

		// For this case there are four matches two should be accepted and two should be blocked
		assertCorrectMatchCountAndAcceptedMatchCount(session,
			"Duplicate Function Instructions Match", 4, 2);
		// Check that all the duplicate matches have the correct statuses
		assertDuplicateMatchStatuses(session);

		// Test that all scores/confidences are values we expect -- There is a 2.0 here, not a 10.0
		// because when a 10.0 is passed into the combined correlator as the confidence value, all
		// the confidences are returned as log10 values which would be 2.0 or less
		assertCorrectScoreAndConfidenceValues(session, "Combined Function and Data Reference Match",
			1.0, 2.0);
		// Keep these numbers so I can do more testing later
		// With the higher score/confidence thresholds, there are less accepted matches
		assertCorrectMatchCountAndAcceptedMatchCount(session,
			"Combined Function and Data Reference Match", 13, 13);
		// Check that all the matches have the correct statuses
		assertCombinedReferenceMatchStatusesHigherScoreAndConfidence(session);

	}

	/*
	 * This tests auto version tracking with the default score/confidence values so some of the
	 * matches are probably not good matches. This was just to make sure that the expected 
	 * results happen in this case and to show difference between this and the more cautious ones.
	 */
	@Test
	public void testRunAutoVT_aLittleLessCautious() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// Score 0.5 and conf threshold 1.0 allow similarity scores of higher than 0.5 for combined 
		// reference correlator and 1.0 and higher for the log 10 confidence score
		boolean success = runAutoVTCommand(0.5, 1.0);
		assertTrue("Auto Version Tracking Command failed to run", success);

		// verify that the default options are what we expect
		// if this assert fails then the follow-on tests will probably fail 
		assertCorrectOptionValues(session, "0.5", "1.0");

		// verify that given the above verified conditions the 
		// exact unique correlators (which have their own tests to verify which matches are
		// correct) return the expected number of possible matches and accepted matches
		// since they are exact and unique and this number is already known based on other tests
		// this is just verifying that what we expect to happen is happening for debug purposes 
		// in case something is changed in the future that would alter these numbers.
		// We need to know that these are as expected before testing the non-exact/unique correlator
		// results that depend on these answers. 
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Symbol Name Match", 203, 203);
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Data Match", 125, 125);
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Function Bytes Match", 18, 18);
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Function Instructions Match",
			47, 47);
		assertCorrectMatchCountAndAcceptedMatchCount(session, "Exact Function Mnemonics Match", 44,
			44);

		// For the duplicate one -- there are four matches two should be accepted and two should be
		// blocked
		assertCorrectMatchCountAndAcceptedMatchCount(session,
			"Duplicate Function Instructions Match", 4, 2);
		// Check that all the duplicate matches have the correct statuses
		assertDuplicateMatchStatuses(session);

		// There are thirty-four possible matches all accepted except one that was blocked from
		// a previous correlator
		assertCorrectMatchCountAndAcceptedMatchCount(session,
			"Combined Function and Data Reference Match", 33, 33);
		// Check that all the matches have the correct statuses
		assertCombinedReferenceMatchStatusesLowerScoreAndConfidence(session);

	}

	@Test
	public void testBlocked() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// This test is testing to make sure that previously blocked matches do not become
		// accepted matches after running Auto VT

		//make a match - do not accept it
		VTMatch match = createMatch(addr("0x000411860", sourceProgram),
			addr("0x00411830", destinationProgram), false);

		//make a second match that conflicts with first match and accept it which will cause the 
		// first match to be blocked
		VTMatch match2 = createMatch(addr("0x4117c0", sourceProgram),
			addr("0x00411830", destinationProgram), true);

		// verify that they have correct statuses
		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(status, VTAssociationStatus.BLOCKED);
		VTAssociationStatus status2 = match2.getAssociation().getStatus();
		assertEquals(status2, VTAssociationStatus.ACCEPTED);

		// run auto VT which would normally accept the match we blocked
		runAutoVTCommand(1.0, 10.0);

		// Now test that the match we blocked is still blocked to verify that auto VT
		// does not accept blocked matches
		assertEquals(
			getMatchStatus(session, "Combined Function and Data Reference Match",
				addr("0x00411860", sourceProgram), addr("0x00411830", destinationProgram)),
			VTAssociationStatus.BLOCKED);
	}

	@Test
	public void testDuplicateMatches_DifferentRegisterOperands_allUnique() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		// Create three functions in both the source and destination program with matching 
		// instructions but different register operands
		byte[] bytes1 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x33, (byte) 0xc0, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,EAX;
		createFunction(sourceProgram, bytes1, addr("0x414c00", sourceProgram));
		createFunction(destinationProgram, bytes1, addr("0x414c00", destinationProgram));

		byte[] bytes2 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x33, (byte) 0xc1, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,ECX;
		createFunction(sourceProgram, bytes2, addr("0x414d00", sourceProgram));
		createFunction(destinationProgram, bytes2, addr("0x414d00", destinationProgram));

		byte[] bytes3 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x33, (byte) 0xc3, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,EBX;
		createFunction(sourceProgram, bytes3, addr("0x414e00", sourceProgram));
		createFunction(destinationProgram, bytes3, addr("0x414e00", destinationProgram));

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// run auto VT 
		runAutoVTCommand(1.0, 10.0);

		// Now test that the correct matches were created based on the duplicate functions we created 
		String correlator = "Duplicate Function Instructions Match";

		assertAcceptedMatch(session, correlator, "0x414c00", "0x414c00");
		assertAcceptedMatch(session, correlator, "0x414d00", "0x414d00");
		assertAcceptedMatch(session, correlator, "0x414e00", "0x414e00");

	}

	@Test
	public void testDuplicateMatches_DifferentRegisterOperands_someNotUnique() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		// Create three functions in both the source and destination program with matching 
		// instructions but different register operands
		byte[] bytes1 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x33, (byte) 0xc0, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,EAX;
		createFunction(sourceProgram, bytes1, addr("0x414c00", sourceProgram));
		createFunction(destinationProgram, bytes1, addr("0x414c00", destinationProgram));

		byte[] bytes2 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x33, (byte) 0xc1, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,ECX;
		createFunction(sourceProgram, bytes2, addr("0x414d00", sourceProgram));
		createFunction(destinationProgram, bytes2, addr("0x414d00", destinationProgram));

		byte[] bytes3 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x33, (byte) 0xc3, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,EBX;
		createFunction(sourceProgram, bytes3, addr("0x414e00", sourceProgram));
		createFunction(destinationProgram, bytes3, addr("0x414e00", destinationProgram));

		// this function is identical to the one above
		byte[] bytes4 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x33, (byte) 0xc3, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,EBX;
		createFunction(sourceProgram, bytes4, addr("0x414f00", sourceProgram));
		createFunction(destinationProgram, bytes4, addr("0x414f00", destinationProgram));

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// run auto VT 
		runAutoVTCommand(1.0, 10.0);

		// Now test that the correct matches were created based on the duplicate functions we created 
		String correlator = "Duplicate Function Instructions Match";

		assertAcceptedMatch(session, correlator, "0x414c00", "0x414c00");
		assertAcceptedMatch(session, correlator, "0x414d00", "0x414d00");
		assertAvailableMatch(session, correlator, "0x414e00", "0x414e00");
		assertAvailableMatch(session, correlator, "0x414f00", "0x414f00");

	}

	@Test
	public void testDuplicateMatches_allIdentical() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		// Create two functions in both the source and destination program with identical bytes
		// Exact bytes will not match it since there is no unique match.
		// AutoVT should also not match them since it can't tell which is which

		byte[] bytes = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x33, (byte) 0xc0, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,EAX;

		createFunction(sourceProgram, bytes, addr("0x414c00", sourceProgram));
		createFunction(destinationProgram, bytes, addr("0x414c00", destinationProgram));
		createFunction(sourceProgram, bytes, addr("0x414d00", sourceProgram));
		createFunction(destinationProgram, bytes, addr("0x414d00", destinationProgram));

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// run auto VT 
		runAutoVTCommand(1.0, 10.0);

		// Test to make sure that they weren't matched by something else first so we can
		// be sure that we are testing just the duplicate test case
		assertNoOtherMatches(session, "Duplicate Function Instructions Match",
			addr("0x414c00", sourceProgram), addr("0x414c00", destinationProgram));
		assertNoOtherMatches(session, "Duplicate Function Instructions Match",
			addr("0x414d00", sourceProgram), addr("0x414d00", destinationProgram));
		assertNoOtherMatches(session, "Duplicate Function Instructions Match",
			addr("0x414c00", sourceProgram), addr("0x414d00", destinationProgram));
		assertNoOtherMatches(session, "Duplicate Function Instructions Match",
			addr("0x414d00", sourceProgram), addr("0x414c00", destinationProgram));

		// Now test that the Auto VT did not accept either
		String correlator = "Duplicate Function Instructions Match";

		assertAvailableMatch(session, correlator, "0x414c00", "0x414c00");
		assertAvailableMatch(session, correlator, "0x414d00", "0x414d00");
		assertAvailableMatch(session, correlator, "0x414c00", "0x414d00");
		assertAvailableMatch(session, correlator, "0x414d00", "0x414c00");
	}

	@Test
	public void testDuplicateMatches_threeIdenticalthreeUnique() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		// Create three functions in both the source and destination program with identical bytes
		// Exact bytes will not match it since there is no unique match.
		// AutoVT should also not match them since it can't tell which is which

		byte[] bytes = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x01, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,1; 

		createFunction(sourceProgram, bytes, addr("0x414c00", sourceProgram));
		createFunction(destinationProgram, bytes, addr("0x414d00", destinationProgram));
		createFunction(sourceProgram, bytes, addr("0x414d00", sourceProgram));
		createFunction(destinationProgram, bytes, addr("0x414e00", destinationProgram));
		createFunction(sourceProgram, bytes, addr("0x414e00", sourceProgram));
		createFunction(destinationProgram, bytes, addr("0x414f00", destinationProgram));

		// Create three functions in each program with same instructions as the above functions but 
		// replace the XOR EAX, 1 with XOR EAX, 2, XOR EAX, 2, XOR EAX, 3 respectively

		byte[] bytes2 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x02, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,2;

		createFunction(sourceProgram, bytes2, addr("0x414f00", sourceProgram));
		createFunction(destinationProgram, bytes2, addr("0x415000", destinationProgram));

		byte[] bytes3 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x03, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,3;

		createFunction(sourceProgram, bytes3, addr("0x415000", sourceProgram));
		createFunction(destinationProgram, bytes3, addr("0x415100", destinationProgram));

		byte[] bytes4 = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x04, (byte) 0x5d, (byte) 0x90, (byte) 0xc3 };  //XOR EAX,4;

		createFunction(sourceProgram, bytes4, addr("0x415100", sourceProgram));
		createFunction(destinationProgram, bytes4, addr("0x415200", destinationProgram));

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// run auto VT 
		runAutoVTCommand(1.0, 10.0);

		// Test to make sure that they weren't matched by something else first so we can
		// be sure that we are testing just duplicate correlator match case
		List<Address> sourceAddrs = new ArrayList<>();
		List<Address> destAddrs = new ArrayList<>();

		sourceAddrs.add(addr("0x414c00", sourceProgram));
		sourceAddrs.add(addr("0x414d00", sourceProgram));
		sourceAddrs.add(addr("0x414e00", sourceProgram));
		sourceAddrs.add(addr("0x414f00", sourceProgram));
		sourceAddrs.add(addr("0x415000", sourceProgram));
		sourceAddrs.add(addr("0x415100", sourceProgram));

		destAddrs.add(addr("0x414d00", destinationProgram));
		destAddrs.add(addr("0x414e00", destinationProgram));
		destAddrs.add(addr("0x414f00", destinationProgram));
		destAddrs.add(addr("0x415000", destinationProgram));
		destAddrs.add(addr("0x415100", destinationProgram));
		destAddrs.add(addr("0x415200", destinationProgram));

		// checks to make sure than no other correlator besides Duplicate one matched them
		for (Address sourceAddr : sourceAddrs) {
			for (Address destAddr : destAddrs) {
				assertNoOtherMatches(session, "Duplicate Function Instructions Match", sourceAddr,
					destAddr);
			}
		}
		// 40 = four for the 2x2 matches that already existed and 36 for the 6x6 matches just created
		// 5 = 2 matches that already existed + 3 valid matches from the ones just created 
		assertCorrectMatchCountAndAcceptedMatchCount(session,
			"Duplicate Function Instructions Match", 40, 5);

		// Now test that the Auto VT duplicate matcher did not accept any matches between the three 
		// identical ones but did accept the unique ones and blocked the ones between the unique ones
		// and the rest
		List<Address> identicalSourceAddrs = new ArrayList<>();
		List<Address> identicalDestAddrs = new ArrayList<>();
		identicalSourceAddrs.add(addr("0x414c00", sourceProgram));
		identicalSourceAddrs.add(addr("0x414d00", sourceProgram));
		identicalSourceAddrs.add(addr("0x414e00", sourceProgram));
		identicalDestAddrs.add(addr("0x414d00", destinationProgram));
		identicalDestAddrs.add(addr("0x414e00", destinationProgram));
		identicalDestAddrs.add(addr("0x414f00", destinationProgram));

		String correlator = "Duplicate Function Instructions Match";

		// Checks that the duplicate identical ones are available matches 
		for (Address sourceAddr : identicalSourceAddrs) {
			for (Address destAddr : identicalDestAddrs) {
				assertAvailableMatch(session, correlator, sourceAddr.toString(),
					destAddr.toString());
			}
		}

		// Checks that the ones with unique matching operands are accepted matches
		assertAcceptedMatch(session, correlator, "0x414f00", "0x415000");
		assertAcceptedMatch(session, correlator, "0x415000", "0x415100");
		assertAcceptedMatch(session, correlator, "0x415100", "0x415200");

		// Check the blocked ones and accepted ones
		List<Address> uniqueSourceAddrs = new ArrayList<>();
		List<Address> uniqueDestAddrs = new ArrayList<>();
		uniqueSourceAddrs.add(addr("0x414f00", sourceProgram));
		uniqueSourceAddrs.add(addr("0x415000", sourceProgram));
		uniqueSourceAddrs.add(addr("0x415100", sourceProgram));
		uniqueDestAddrs.add(addr("0x415000", destinationProgram));
		uniqueDestAddrs.add(addr("0x415100", destinationProgram));
		uniqueDestAddrs.add(addr("0x415200", destinationProgram));

		// The unique ones should be accepted matches
		// The the non-matching unique ones should be blocked from each other
		for (int i = 0; i < uniqueSourceAddrs.size(); i++) {
			for (int j = 0; j < uniqueDestAddrs.size(); j++) {
				// the ones at the same index in the lists should be the accepted matches
				if (i == j) {
					assertAcceptedMatch(session, correlator, uniqueSourceAddrs.get(i).toString(),
						uniqueDestAddrs.get(j).toString());
				}
				// the rest should be blocked matches
				else {
					assertBlockedMatch(session, correlator, uniqueSourceAddrs.get(i).toString(),
						uniqueDestAddrs.get(j).toString());
				}
			}
		}
		// The unique ones shouldn't match any of the identical ones so test each list against the other
		for (Address sourceAddr : identicalSourceAddrs) {
			for (Address destAddr : uniqueDestAddrs) {
				assertBlockedMatch(session, correlator, sourceAddr.toString(), destAddr.toString());
			}
		}

		for (Address sourceAddr : uniqueSourceAddrs) {
			for (Address destAddr : identicalDestAddrs) {
				assertBlockedMatch(session, correlator, sourceAddr.toString(), destAddr.toString());
			}
		}
	}

	@Test
	public void testDuplicateMatches_DifferentConstantOperands_allUnique() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		// Create three functions in both the source and destination program with matching 
		// instructions but different constant operands and a call with different offset so that
		// the exact bytes matcher doesn't find it first but it still has the same instructions

		byte[] retFunction = { (byte) 0xc3 };

		byte[] bytes1source = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x01, (byte) 0xe8, (byte) 0x04, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x5d, (byte) 0xc3 };  //XOR EAX,1; 
		byte[] bytes1dest = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x01, (byte) 0xe8, (byte) 0x08, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x5d, (byte) 0xc3 };  //XOR EAX,1; 

		createFunction(sourceProgram, retFunction, addr("0x414c11", sourceProgram));
		createFunction(sourceProgram, bytes1source, addr("0x414c00", sourceProgram));
		createFunction(destinationProgram, retFunction, addr("0x414c15", destinationProgram));
		createFunction(destinationProgram, bytes1dest, addr("0x414c00", destinationProgram));
		byte[] bytes2source = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x02, (byte) 0xe8, (byte) 0x04, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x5d, (byte) 0xc3 };  //XOR EAX,2;
		byte[] bytes2dest = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x02, (byte) 0xe8, (byte) 0x08, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x5d, (byte) 0xc3 };  //XOR EAX,2;
		createFunction(sourceProgram, retFunction, addr("0x414d11", sourceProgram));

		createFunction(sourceProgram, bytes2source, addr("0x414d00", sourceProgram));
		createFunction(destinationProgram, retFunction, addr("0x414d15", destinationProgram));

		createFunction(destinationProgram, bytes2dest, addr("0x414d00", destinationProgram));

		byte[] bytes3source = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x03, (byte) 0xe8, (byte) 0x04, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x5d, (byte) 0xc3 };  //XOR EAX,3;
		byte[] bytes3dest = { (byte) 0x8b, (byte) 0xff, (byte) 0x55, (byte) 0x8b, (byte) 0xec,
			(byte) 0x83, (byte) 0xf0, (byte) 0x03, (byte) 0xe8, (byte) 0x08, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x5d, (byte) 0xc3 };  //XOR EAX,3;

		createFunction(sourceProgram, retFunction, addr("0x414e11", sourceProgram));
		createFunction(sourceProgram, bytes3source, addr("0x414e00", sourceProgram));
		createFunction(destinationProgram, retFunction, addr("0x414e15", destinationProgram));
		createFunction(destinationProgram, bytes3dest, addr("0x414e00", destinationProgram));

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// run auto VT 
		runAutoVTCommand(1.0, 10.0);

		// Test to make sure that they weren't matched by something else first so we can
		// be sure that we are testing just the duplicate test case
		assertNoOtherMatches(session, "Duplicate Function Instructions Match",
			addr("0x414c00", sourceProgram), addr("0x414c00", destinationProgram));
		assertNoOtherMatches(session, "Duplicate Function Instructions Match",
			addr("0x414d00", sourceProgram), addr("0x414d00", destinationProgram));
		assertNoOtherMatches(session, "Duplicate Function Instructions Match",
			addr("0x414e00", sourceProgram), addr("0x414e00", destinationProgram));

		// Now test that the correct matches were created based on the duplicate functions we created
		String correlator = "Duplicate Function Instructions Match";

		assertAcceptedMatch(session, correlator, "0x414c00", "0x414c00");
		assertAcceptedMatch(session, correlator, "0x414d00", "0x414d00");
		assertAcceptedMatch(session, correlator, "0x414e00", "0x414e00");
	}

	/*
	 * This tests whether the markup from a function gets applied to the destination function
	 * for the case where all instructions line up exactly between both functions. It tests 
	 * the apply markup path for unique matches. 
	 */
	@Test
	public void testMarkup_AllMarkupShouldApply_UniqueMatch() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// Put some markup in the tested source function EOL comments
		Listing sourceListing = sourceProgram.getListing();
		Function sourceFunction =
			sourceProgram.getFunctionManager().getFunctionAt(addr("0x411b80", sourceProgram));
		CodeUnitIterator sourceCodeUnits =
			sourceListing.getCodeUnits(sourceFunction.getBody(), true);

		String transactionName = "Set Test Comments";
		int startTransaction = sourceProgram.startTransaction(transactionName);

		int numComments = 0;
		while (sourceCodeUnits.hasNext()) {
			CodeUnit cu = sourceCodeUnits.next();
			Address addr = cu.getAddress();
			sourceListing.setComment(addr, CodeUnit.EOL_COMMENT, "Test Comment " + numComments++);
		}
		sourceProgram.endTransaction(startTransaction, true);

		// run Auto VT
		boolean success = runAutoVTCommand(1.0, 10.0);
		assertTrue("Auto Version Tracking Command failed to run", success);

		// Check that the match we are interested in got accepted
		String correlator = "Combined Function and Data Reference Match";
		assertAcceptedMatch(session, correlator, "0x411b80", "0x411b60");

		// Check that the markup all got moved over
		Listing destListing = destinationProgram.getListing();
		Function destFunction =
			destinationProgram.getFunctionManager().getFunctionAt(addr("0x411b60", sourceProgram));
		CodeUnitIterator destCodeUnits = destListing.getCodeUnits(destFunction.getBody(), true);

		numComments = 0;
		while (destCodeUnits.hasNext()) {
			CodeUnit cu = destCodeUnits.next();
			Address addr = cu.getAddress();
			assertEquals("Test Comment " + numComments++,
				destListing.getComment(CodeUnit.EOL_COMMENT, addr));
		}
	}

	/*
	 * This tests whether the markup from a function gets applied to the destination function
	 * for the case where all instructions line up exactly between both functions. It tests 
	 * the apply markup path for duplicate matches. 
	 */
	@Test
	public void testMarkup_AllMarkupShouldApply_DuplicateMatch() throws Exception {

		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// Put some markup in the tested source function EOL comments
		Listing sourceListing = sourceProgram.getListing();
		Function sourceFunction =
			sourceProgram.getFunctionManager().getFunctionAt(addr("0x412300", sourceProgram));
		CodeUnitIterator sourceCodeUnits =
			sourceListing.getCodeUnits(sourceFunction.getBody(), true);

		String transactionName = "Set Test Comments";
		int startTransaction = sourceProgram.startTransaction(transactionName);

		int numComments = 0;
		while (sourceCodeUnits.hasNext()) {
			CodeUnit cu = sourceCodeUnits.next();
			Address addr = cu.getAddress();
			sourceListing.setComment(addr, CodeUnit.EOL_COMMENT, "Test Comment " + numComments++);
		}
		sourceProgram.endTransaction(startTransaction, true);

		// run Auto VT
		boolean success = runAutoVTCommand(1.0, 10.0);
		assertTrue("Auto Version Tracking Command failed to run", success);

		// Check that the match we are interested in got accepted
		String correlator = "Duplicate Function Instructions Match";
		assertAcceptedMatch(session, correlator, "0x412300", "0x4122e0");

		// Check that the markup all got moved over
		Listing destListing = destinationProgram.getListing();
		Function destFunction =
			destinationProgram.getFunctionManager().getFunctionAt(addr("0x4122e0", sourceProgram));
		CodeUnitIterator destCodeUnits = destListing.getCodeUnits(destFunction.getBody(), true);

		numComments = 0;
		while (destCodeUnits.hasNext()) {
			CodeUnit cu = destCodeUnits.next();
			Address addr = cu.getAddress();
			assertEquals("Test Comment " + numComments++,
				destListing.getComment(CodeUnit.EOL_COMMENT, addr));
		}
	}

	/*
	 * This tests whether the markup from a function gets applied to the destination function
	 * for the case where NOT all of the instructions line up exactly between both functions. It
	 * makes sure the markup that is in matching code blocks gets applied but not in the areas
	 * where there isn't a matching code block.
	 */
	@Test
	public void testMarkup_MissingDestinationAddresses() throws Exception {

		// Override the setup to switch the source and destination programs.
		// This is because the destination program has a sample match where the length
		// of a matching function is greater than the one in the source program and 
		// it is needed to test this case.

		sourceProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);

		// Now put some markup in the new source function to test such that there is a 
		// comment at each code unit called Test Comment "n" where n is a one up value starting
		// at 0
		Listing sourceListing = sourceProgram.getListing();
		Function sourceFunction =
			sourceProgram.getFunctionManager().getFunctionAt(addr("0x4118c0", sourceProgram));
		CodeUnitIterator codeUnits = sourceListing.getCodeUnits(sourceFunction.getBody(), true);

		String transactionName = "Set Test Comments";
		int startTransaction = sourceProgram.startTransaction(transactionName);

		int numComments = 0;
		while (codeUnits.hasNext()) {
			CodeUnit cu = codeUnits.next();
			Address addr = cu.getAddress();
			sourceListing.setComment(addr, CodeUnit.EOL_COMMENT, "Test Comment " + numComments++);
		}
		sourceProgram.endTransaction(startTransaction, true);

		session = env.createSession(sourceProgram, destinationProgram);

		env.showTool();
		controller = env.getVTController();

		// Now run the AutoVT command with lower confidence thresholds to allow the match we want to 
		// test in as a match
		boolean success = runAutoVTCommand(0.5, 1.0);
		assertTrue("Auto Version Tracking Command failed to run", success);

		// Check that the match we are interested in got accepted
		String correlator = "Combined Function and Data Reference Match";
		assertAcceptedMatch(session, correlator, "0x4118c0", "0x4118f0");

		// Check that the expected comments were moved over
		// The case we have is where the source function has a chunk of five code units in the 
		// middle that isn't in the destination function. We need to test that the top set of code 
		// units have comments Test Comment 0-n and then skip the five then test the rest that
		// should match until the end of the function
		Listing destListing = destinationProgram.getListing();

		// Get the first set of comments that should line up and test them first
		AddressSet topAddressSet = destinationProgram.getAddressFactory().getAddressSet(
			addr("0x4118f0", destinationProgram), addr("0x4119ad", destinationProgram));
		CodeUnitIterator codeUnitsDestTop = destListing.getCodeUnits(topAddressSet, true);

		numComments = 0;
		while (codeUnitsDestTop.hasNext()) {
			CodeUnit cu = codeUnitsDestTop.next();
			Address addr = cu.getAddress();
			assertEquals("Test Comment " + numComments++,
				destListing.getComment(CodeUnit.EOL_COMMENT, addr));
		}

		// Now check the one that should not have a comment at all
		assertEquals(null,
			destListing.getComment(CodeUnit.EOL_COMMENT, addr("0x4119af", destinationProgram)));

		// Now get the bottom section 
		AddressSet bottomAddressSet = destinationProgram.getAddressFactory().getAddressSet(
			addr("0x4119b1", destinationProgram), addr("0x4119e9", destinationProgram));
		CodeUnitIterator codeUnitsDestBottom = destListing.getCodeUnits(bottomAddressSet, true);

		// The five comments from the source should not get moved over so skip those and test that
		// the rest have the correct comments
		numComments += 5;
		while (codeUnitsDestBottom.hasNext()) {
			CodeUnit cu = codeUnitsDestBottom.next();
			Address addr = cu.getAddress();
			assertEquals(destListing.getComment(CodeUnit.EOL_COMMENT, addr),
				"Test Comment " + numComments++);
		}
	}

	private VTMatch createMatch(Address sourceAddress, Address destinationAddress,
			boolean setAccepted) throws VTAssociationStatusException {
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

	private void assertCorrectMatchCountAndAcceptedMatchCount(VTSession vtSession,
			String correlatorName, int expectedMatchCount, int expectedAcceptedMatchCount) {
		assertEquals(expectedMatchCount, getVTMatchSet(vtSession, correlatorName).getMatchCount());
		assertEquals(expectedAcceptedMatchCount, getNumAcceptedMatches(vtSession, correlatorName));
	}

	private boolean runAutoVTCommand(double minReferenceCorrelatorScore,
			double minReferenceCorrelatorConfidence) {
		AtomicBoolean result = new AtomicBoolean();
		runSwing(() -> {
			String transactionName = "Auto Version Tracking Test";
			int startTransaction = session.startTransaction(transactionName);

			AutoVersionTrackingCommand vtCommand = new AutoVersionTrackingCommand(controller,
				session, minReferenceCorrelatorScore, minReferenceCorrelatorConfidence);
			result.set(vtCommand.applyTo(session, TaskMonitor.DUMMY));

			session.endTransaction(startTransaction, result.get());
		});
		return result.get();
	}

	private VTMatchSet getVTMatchSet(VTSession vtSession, String correlatorName) {
		List<VTMatchSet> matchSets = vtSession.getMatchSets();
		Iterator<VTMatchSet> iterator = matchSets.iterator();
		while (iterator.hasNext()) {
			VTMatchSet matches = iterator.next();
			if (matches.getProgramCorrelatorInfo().getName().equals(correlatorName)) {
				return matches;
			}
		}

		fail("Unable to find a match set for '" + correlatorName + "'");
		return null; /// can't get here
	}

	private boolean assertCorrectScoreAndConfidenceValues(VTSession vtSession,
			String correlatorName, double score, double confidence) {
		VTMatchSet matches = getVTMatchSet(vtSession, correlatorName);

		Msg.info(this, score + " " + confidence);
		Iterator<VTMatch> it = matches.getMatches().iterator();
		while (it.hasNext()) {
			VTMatch match = it.next();
			VTAssociationStatus status = match.getAssociation().getStatus();
			if (status.equals(VTAssociationStatus.ACCEPTED)) {
				Msg.info(this,
					match.getSourceAddress().toString() + " " +
						match.getDestinationAddress().toString() + " " +
						match.getSimilarityScore().getFormattedScore() + " " +
						match.getConfidenceScore().getFormattedLog10Score());
				if (match.getSimilarityScore().getScore() < score ||
					match.getConfidenceScore().getScore() < confidence) {
					return false;
				}
			}
		}
		return true;
	}

	private int getNumAcceptedMatches(VTSession vtSession, String correlatorName) {
		VTMatchSet matches = getVTMatchSet(vtSession, correlatorName);

		int count = 0;
		Iterator<VTMatch> it = matches.getMatches().iterator();
		while (it.hasNext()) {
			VTMatch match = it.next();
			VTAssociationStatus status = match.getAssociation().getStatus();
			if (status.equals(VTAssociationStatus.ACCEPTED)) {
				count++;
			}
		}
		return count;
	}

	private VTAssociationStatus getMatchStatus(VTSession vtSession, String correlatorName,
			Address sourceAddress, Address destinationAddress) {

		VTMatchSet matches = getVTMatchSet(vtSession, correlatorName);

		Iterator<VTMatch> it = matches.getMatches().iterator();
		while (it.hasNext()) {
			VTMatch match = it.next();
			if (match.getSourceAddress().equals(sourceAddress) &&
				match.getDestinationAddress().equals(destinationAddress)) {
				return match.getAssociation().getStatus();
			}
		}
		return null;
	}

	private VTMatch getMatch(VTMatchSet matches, Address sourceAddress,
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

	// This method asserts that none of the other correlators besides the one passed in have made
	// match between the two addresses
	private boolean assertNoOtherMatches(VTSession vtSession, String correlatorName,
			Address sourceAddress, Address destinationAddress) {
		List<VTMatchSet> matchSets = vtSession.getMatchSets();

		for (VTMatchSet matchSet : matchSets) {
			// Ignore the matchSet with the given correlator name 
			if (matchSet.getProgramCorrelatorInfo().getName().equals(correlatorName)) {
				continue;
			}
			if (getMatch(matchSet, sourceAddress, destinationAddress) != null) {
				return false;
			}
		}
		return true;
	}

	// verify that the default options are what we expect
	private void assertCorrectOptionValues(VTSession vtSession, String minRefScore,
			String minRefConf) {
		Options options = getCorrelatorOptions(vtSession, "Exact Symbol Name Match");
		assertNotNull(options);
		assertExpectedOption(options, "Include External Function Symbols", "true");
		assertExpectedOption(options, "Minimum Symbol Name Length", "3");

		options = getCorrelatorOptions(vtSession, "Exact Data Match");
		assertNotNull(options);
		assertExpectedOption(options, "Data Alignment", "1");
		assertExpectedOption(options, "Data Maximum Size", "1048576");
		assertExpectedOption(options, "Data Minimum Size", "5");
		assertExpectedOption(options, "Skip Homogenous Data", "true");

		options = getCorrelatorOptions(vtSession, "Exact Function Bytes Match");
		assertNotNull(options);
		assertExpectedOption(options, "Function Minimum Size", "10");

		options = getCorrelatorOptions(vtSession, "Exact Function Instructions Match");
		assertNotNull(options);
		assertExpectedOption(options, "Function Minimum Size", "10");

		options = getCorrelatorOptions(vtSession, "Exact Function Mnemonics Match");
		assertNotNull(options);
		assertExpectedOption(options, "Function Minimum Size", "10");

		options = getCorrelatorOptions(vtSession, "Duplicate Function Instructions Match");
		assertNotNull(options);
		assertExpectedOption(options, "Function Minimum Size", "10");

		options = getCorrelatorOptions(vtSession, "Combined Function and Data Reference Match");
		assertNotNull(options);
		assertExpectedOption(options, "Confidence threshold (info content)", minRefConf);
		assertExpectedOption(options, "Memory model", "Large (faster)");
		assertExpectedOption(options, "Minimum similarity threshold (score)", minRefScore);
		assertExpectedOption(options, "Refine Results", "true");
	}

	// These are the already existing duplicate matches from Wallace programs
	private void assertDuplicateMatchStatuses(VTSession vtSession) {

		String correlator = "Duplicate Function Instructions Match";
		assertAcceptedMatch(vtSession, correlator, "0x412300", "0x4122e0");
		assertAcceptedMatch(vtSession, correlator, "0x412330", "0x412310");
		assertBlockedMatch(vtSession, correlator, "0x412300", "0x412310");
		assertBlockedMatch(vtSession, correlator, "0x412330", "0x4122e0");
	}

	// These are the matches when score is 1.0 and log 10 conf threshold is 2.0 
	private void assertCombinedReferenceMatchStatusesHigherScoreAndConfidence(VTSession vtSession) {

		String correlator = "Combined Function and Data Reference Match";

		assertAcceptedMatch(vtSession, correlator, "0x00411700", "0x004116f0");
		assertAcceptedMatch(vtSession, correlator, "0x00411860", "0x00411830");
		assertAcceptedMatch(vtSession, correlator, "0x00411ab0", "0x00411a90");
		assertAcceptedMatch(vtSession, correlator, "0x00411b80", "0x00411b60");
		assertAcceptedMatch(vtSession, correlator, "0x00411bb0", "0x00411b90");
		assertAcceptedMatch(vtSession, correlator, "0x00411c70", "0x00411c50");
		assertAcceptedMatch(vtSession, correlator, "0x00411ee0", "0x00411ec0");
		assertAcceptedMatch(vtSession, correlator, "0x0412380", "0x00412360");
		assertAcceptedMatch(vtSession, correlator, "0x04123f0", "0x004123d0");
		assertAcceptedMatch(vtSession, correlator, "0x0412950", "0x00412930");
		assertAcceptedMatch(vtSession, correlator, "0x04130d0", "0x004130b0");
		assertAcceptedMatch(vtSession, correlator, "0x04134e0", "0x004134c0");
		assertAcceptedMatch(vtSession, correlator, "0x0413520", "0x00413500");
	}

	// These are the matches when score is 0.5 and conf is 1.0
	private void assertCombinedReferenceMatchStatusesLowerScoreAndConfidence(VTSession vtSession) {

		// These have all been either accepted by a previous correlator or the Combined
		// one
		String correlator = "Combined Function and Data Reference Match";

		assertAcceptedMatch(vtSession, correlator, "0x004115d0", "0x004115c0");
		assertAcceptedMatch(vtSession, correlator, "0x00411700", "0x004116f0");
		assertAcceptedMatch(vtSession, correlator, "0x00411860", "0x00411830");
		assertAcceptedMatch(vtSession, correlator, "0x004118f0", "0x004118c0");
		assertAcceptedMatch(vtSession, correlator, "0x00411a30", "0x00411a10");
		assertAcceptedMatch(vtSession, correlator, "0x00411ab0", "0x00411a90");
		assertAcceptedMatch(vtSession, correlator, "0x00411b80", "0x00411b60");
		assertAcceptedMatch(vtSession, correlator, "0x00411bb0", "0x00411b90");
		assertAcceptedMatch(vtSession, correlator, "0x00411c70", "0x00411c50");
		assertAcceptedMatch(vtSession, correlator, "0x00411da0", "0x00411d80");
		assertAcceptedMatch(vtSession, correlator, "0x00411dc0", "0x00411da0");
		assertAcceptedMatch(vtSession, correlator, "0x00411e70", "0x00411e50");
		assertAcceptedMatch(vtSession, correlator, "0x00411ee0", "0x00411ec0");
		assertAcceptedMatch(vtSession, correlator, "0x00411f00", "0x00411ee0");
		assertAcceptedMatch(vtSession, correlator, "0x04122b0", "0x00412290");
		assertAcceptedMatch(vtSession, correlator, "0x0412380", "0x00412360");
		assertAcceptedMatch(vtSession, correlator, "0x04123f0", "0x004123d0");
		assertAcceptedMatch(vtSession, correlator, "0x0412810", "0x004127f0");
		assertAcceptedMatch(vtSession, correlator, "0x0412950", "0x00412930");
		assertAcceptedMatch(vtSession, correlator, "0x0412ad0", "0x00412ab0");
		assertAcceptedMatch(vtSession, correlator, "0x0412b60", "0x00412b40");
		assertAcceptedMatch(vtSession, correlator, "0x0412df0", "0x00412dd0");
		assertAcceptedMatch(vtSession, correlator, "0x0412e70", "0x00412e50");
		assertAcceptedMatch(vtSession, correlator, "0x0412e90", "0x00412e70");
		assertAcceptedMatch(vtSession, correlator, "0x0412ee0", "0x00412ec0");
		assertAcceptedMatch(vtSession, correlator, "0x0412fa0", "0x00412f80");
		assertAcceptedMatch(vtSession, correlator, "0x0413073", "0x00413053");
		assertAcceptedMatch(vtSession, correlator, "0x04130d0", "0x004130b0");
		assertAcceptedMatch(vtSession, correlator, "0x0413110", "0x004130f0");
		assertAcceptedMatch(vtSession, correlator, "0x0413370", "0x00413350");
		assertAcceptedMatch(vtSession, correlator, "0x04134e0", "0x004134c0");
		assertAcceptedMatch(vtSession, correlator, "0x0413520", "0x00413500");
		assertAcceptedMatch(vtSession, correlator, "0x0413890", "0x00413870");
	}

	private void assertAcceptedMatch(VTSession vtSession, String correlatorName,
			String sourceAddress, String destinationAddress) {
		assertEquals(VTAssociationStatus.ACCEPTED, getMatchStatus(vtSession, correlatorName,
			addr(sourceAddress, sourceProgram), addr(destinationAddress, destinationProgram)));
	}

	private void assertBlockedMatch(VTSession vtSession, String correlatorName,
			String sourceAddress, String destinationAddress) {
		assertEquals(VTAssociationStatus.BLOCKED, getMatchStatus(vtSession, correlatorName,
			addr(sourceAddress, sourceProgram), addr(destinationAddress, destinationProgram)));
	}

	private void assertAvailableMatch(VTSession vtSession, String correlatorName,
			String sourceAddress, String destinationAddress) {
		assertEquals(VTAssociationStatus.AVAILABLE, getMatchStatus(vtSession, correlatorName,
			addr(sourceAddress, sourceProgram), addr(destinationAddress, destinationProgram)));
	}

	private Options getCorrelatorOptions(VTSession vtSession, String correlatorName) {
		VTMatchSet vtMatchSet = getVTMatchSet(vtSession, correlatorName);
		Options options = vtMatchSet.getProgramCorrelatorInfo().getOptions();
		return options;
	}

	private void assertExpectedOption(Options options, String optionName,
			String expectedOptionValue) {
		assertTrue(options.contains(optionName));
		assertEquals(expectedOptionValue, options.getValueAsString(optionName));
	}

	// returns true if function created successfully
	private boolean createFunction(Program program, byte[] bytes, Address address)
			throws MemoryAccessException, InvalidInputException, OverlappingFunctionException {

		String transactionName = "Create function";
		int startTransaction = program.startTransaction(transactionName);

		program.getMemory().setBytes(address, bytes);
		AddressSet addressSet =
			program.getAddressFactory().getAddressSet(address, address.add(bytes.length - 1));

		DisassembleCommand disassemble = new DisassembleCommand(address, addressSet, false);
		boolean disassembled = disassemble.applyTo(program);
		if (!disassembled) {
			return false;
		}
		FunctionManager functionManager = program.getFunctionManager();
		Function createFunction = functionManager.createFunction("FUN_" + address.toString(),
			address, addressSet, SourceType.DEFAULT);
		if (createFunction == null) {
			return false;
		}

		program.endTransaction(startTransaction, true);
		return true;

	}

}
