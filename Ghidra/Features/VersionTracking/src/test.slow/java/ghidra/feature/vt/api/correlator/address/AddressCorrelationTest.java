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
package ghidra.feature.vt.api.correlator.address;

import static ghidra.feature.vt.db.VTTestUtils.*;
import static org.junit.Assert.*;

import java.util.Collection;
import java.util.List;

import org.junit.*;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.*;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.AddressCorrelation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Tests to verify that the correct address correlation is being determined and used for obtaining
 * destination addresses for markup items of a function match.
 */
public class AddressCorrelationTest extends AbstractGhidraHeadedIntegrationTest {

	protected static final String TEST_SOURCE_PROGRAM_NAME = "VersionTracking/WallaceSrc";
	protected static final String TEST_DESTINATION_PROGRAM_NAME = "VersionTracking/WallaceVersion2";

	protected VTTestEnv vtTestEnv;
	protected VTProgramCorrelator correlator;
	protected Program sourceProgram;
	protected Program destinationProgram;
	protected VTController controller;
	protected VTSession session;
	protected Address sourceAddress;
	protected Address destinationAddress;
	protected VTMatch testMatch;
	protected Function sourceFunction;
	protected Function destinationFunction;

	@Before
	public void setUp() throws Exception {
		vtTestEnv = new VTTestEnv();
	}

	@After
	public void tearDown() throws Exception {
		sourceProgram = null;
		destinationProgram = null;
		session = null;
		controller = null;
		correlator = null;
		vtTestEnv.dispose();
	}

	@Test
	public void testExactMatchBytes() throws Exception {
		// Test a function match created by the Exact Bytes Match correlator.
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addComment(CodeUnit.EOL_COMMENT, "0x0041222b", "Exact bytes comment.");
		addProgramCorrelation(new ExactMatchBytesProgramCorrelatorFactory());
		useMatch("0x00412210", "0x004121f0");
		checkAddressCorrelation(StraightLineCorrelation.NAME);
		checkCommentMarkup(EolCommentMarkupType.INSTANCE, "0x0041222b", "Exact bytes comment.",
			"0x0041220b");
		checkMarkupDestinationSource(StraightLineCorrelation.NAME, false);
	}

	@Test
	public void testExactMatchMnemonics() throws Exception {
		// Test a function match created by the Exact Mnemonics Match correlator.
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addComment(CodeUnit.PRE_COMMENT, "0x00412988", "Exact mnemonics comment.");
		addProgramCorrelation(new ExactMatchMnemonicsProgramCorrelatorFactory());
		useMatch("0x00412950", "0x00412930");
		checkAddressCorrelation(StraightLineCorrelation.NAME);
		checkCommentMarkup(PreCommentMarkupType.INSTANCE, "0x00412988", "Exact mnemonics comment.",
			"0x00412968");
		checkMarkupDestinationSource(StraightLineCorrelation.NAME, false);
	}

	@Test
	public void testExactMatchInstructions() throws Exception {
		// Test a function match created by the Exact Instructions Match correlator.
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addComment(CodeUnit.POST_COMMENT, "0x004129a2", "Exact instructions comment.");
		addProgramCorrelation(new ExactMatchInstructionsProgramCorrelatorFactory());
		useMatch("0x00412950", "0x00412930");
		checkAddressCorrelation(StraightLineCorrelation.NAME);
		checkCommentMarkup(PostCommentMarkupType.INSTANCE, "0x004129a2",
			"Exact instructions comment.", "0x00412982");
		checkMarkupDestinationSource(StraightLineCorrelation.NAME, false);
	}

	@Test
	public void testSimilarSymbolName() throws Exception {
		// Test a function match created by the Similar Symbol Name correlator where the 
		// two programs are for the same language and processor.
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addComment(CodeUnit.EOL_COMMENT, "0x004126dd", "Similar name eol comment.");
		addComment(CodeUnit.PRE_COMMENT, "0x004126d7", "Similar name pre comment.");
		addProgramCorrelation(new SimilarSymbolNameProgramCorrelatorFactory());
		useMatch("0x00412690", "0x00412720");
		checkAddressCorrelation(VTHashedFunctionAddressCorrelation.NAME);
		checkCommentMarkup(EolCommentMarkupType.INSTANCE, "0x004126dd",
			"Similar name eol comment.", "0x0041277f");
		checkCommentMarkup(PreCommentMarkupType.INSTANCE, "0x004126d7",
			"Similar name pre comment.", "NO_ADDRESS");
		checkMarkupDestinationSource(VTHashedFunctionAddressCorrelation.NAME, true);
	}

	@Test
	public void testSimilarSymbolNameDiffLanguages() throws Exception {
		// Test a function match created by the Similar Symbol Name correlator where the 
		// two programs are for different processors.
		Program languageProgram1 = buildProgram1("language1");
		Program languageProgram2 = buildProgram2("language2");

		createSession(languageProgram1, languageProgram2);
		vtTestEnv.showTool();
		addComment(CodeUnit.PLATE_COMMENT, "0x00401003",
			"Similar name plate comment not at entry.");
		addProgramCorrelation(new SimilarSymbolNameProgramCorrelatorFactory());
		useMatch("0x00401000", "0x00402000");
		checkAddressCorrelation(LinearFunctionAddressCorrelation.NAME);
		// Check for our linear function correlation even though destination will be offcut.
		checkCommentMarkup(PlateCommentMarkupType.INSTANCE, "0x00401003",
			"Similar name plate comment not at entry.", "0x00402003");
		checkMarkupDestinationSource(LinearFunctionAddressCorrelation.NAME, false);
	}

	@Test
	public void testSimilarSymbolNameDiffLanguages2() throws Exception {
		// Test a function match created by the Similar Symbol Name correlator where the 
		// two programs are for different languages but the same processor with different
		// instructions.
		Program languageProgram1 = buildProgram1("language1");
		Program languageProgram2 = buildProgram3("language3");

		createSession(languageProgram1, languageProgram2);
		vtTestEnv.showTool();
		addComment(CodeUnit.EOL_COMMENT, "0x00401003", "Similar name eol comment.");
		addProgramCorrelation(new SimilarSymbolNameProgramCorrelatorFactory());
		useMatch("0x00401000", "0x00402000");
		checkAddressCorrelation(VTHashedFunctionAddressCorrelation.NAME);
		checkCommentMarkup(EolCommentMarkupType.INSTANCE, "0x00401003",
			"Similar name eol comment.", "NO_ADDRESS");
		checkMarkupDestinationSource(VTHashedFunctionAddressCorrelation.NAME, true);
	}

	@Test
	public void testEntryPointPlateCommentMatchingInstructions() throws Exception {
		// Test that plate comments should have a destination address if the 
		// instructions can be correlated, and entry point plates should get the other 
		// function entry point as the destination. This uses a function match created by 
		// the Similar Symbol Name correlator where the two programs are for different 
		// processors with matching instructions. 
		Program p1 = buildProgram1("language1");
		Program p2 = buildProgram2("language2");

		createSession(p1, p2);
		vtTestEnv.showTool();
		addComment(CodeUnit.PLATE_COMMENT, "0x00401000", "First plate comment.");
		addComment(CodeUnit.PLATE_COMMENT, "0x00401003", "Second plate comment.");
		addProgramCorrelation(new SimilarSymbolNameProgramCorrelatorFactory());
		useMatch("0x00401000", "0x00402000");
		checkAddressCorrelation(LinearFunctionAddressCorrelation.NAME);
		// Verify the entry point plate comment markup has a destination address.
		checkCommentMarkup(PlateCommentMarkupType.INSTANCE, "0x00401000", "First plate comment.",
			"0x00402000");
		assertEquals(addr("0x00402000", p2), getMatchingDestAddress("0x00401000")); // Expects a correlated address.
		// Verify the non-entry point plate comment markup also has a destination address.
		checkCommentMarkup(PlateCommentMarkupType.INSTANCE, "0x00401003", "Second plate comment.",
			"0x00402003");
		assertEquals(addr("0x00402003", p2), getMatchingDestAddress("0x00401003")); // Expects a correlated address.
		checkMarkupDestinationSource(LinearFunctionAddressCorrelation.NAME, true);
	}

	@Test
	public void testEntryPointPlateCommentDifferringInstructions() throws Exception {
		// Test that plate comments shouldn't have a destination address if the 
		// instructions can't be correlated, except entry point plates should get the other 
		// function entry point as the destination. This uses a function match created by 
		// the Similar Symbol Name correlator where the two programs are for different 
		// languages but the same processor with different instructions. 
		Program languageProgram1 = buildProgram1("language1");
		Program languageProgram2 = buildProgram3("language3");

		createSession(languageProgram1, languageProgram2);
		vtTestEnv.showTool();
		addComment(CodeUnit.PLATE_COMMENT, "0x00401000", "First plate comment.");
		addComment(CodeUnit.PLATE_COMMENT, "0x00401003", "Second plate comment.");
		addProgramCorrelation(new SimilarSymbolNameProgramCorrelatorFactory());
		useMatch("0x00401000", "0x00402000");
		checkAddressCorrelation(VTHashedFunctionAddressCorrelation.NAME);
		// Verify the entry point plate comment markup has a destination address.
		checkCommentMarkup(PlateCommentMarkupType.INSTANCE, "0x00401000", "First plate comment.",
			"0x00402000");
		assertNull(getMatchingDestAddress("0x00401000")); // Expects no correlated address.
		// Verify the non-entry point plate comment markup does not have a destination address.
		checkCommentMarkup(PlateCommentMarkupType.INSTANCE, "0x00401003", "Second plate comment.",
			"NO_ADDRESS");
		assertNull(getMatchingDestAddress("0x00401003")); // Expects no correlated address.
		checkMarkupDestinationSource(VTHashedFunctionAddressCorrelation.NAME, true);
	}

//==================================================================================================
// Helper Methods
//==================================================================================================	

	/**
	 * Gets the destination address that has been correlated to the indicated source address
	 * for the current function match that has been established in the test.
	 * @param srcAddressStr the source address
	 * @return the matching destination address. Otherwise null if the address correlation for
	 * the match couldn't determine a matching address.
	 */
	private Address getMatchingDestAddress(String srcAddressStr) {
		Address srcAddress = addr(srcAddressStr, sourceProgram);
		AddressCorrelation actualCorrelator =
			controller.getCorrelator(sourceFunction, destinationFunction);
		AddressRange destRange = null;
		try {
			destRange =
				actualCorrelator.getCorrelatedDestinationRange(srcAddress, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// Do nothing. let this return null.
		}
		return (destRange != null) ? destRange.getMinAddress() : null;
	}

	private Program buildProgram1(String name) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._X86);
		Program p = builder.getProgram();
		builder.createMemory("text", "0x00401000", 0x100);
		builder.setBytes("0x00401000", "8b ff 55 8b ec c3");
		builder.disassemble("0x00401000", 6);
		Function function = builder.createFunction("0x00401000");
		int txID = p.startTransaction("Setting Function Name");
		boolean commit = false;
		try {
			function.setName("MyFunctionAB", SourceType.USER_DEFINED);
			Listing listing = p.getListing();
			CodeUnit cu = listing.getCodeUnitAt(function.getEntryPoint());
			cu.setComment(CodeUnit.EOL_COMMENT, "A sample end of line comment");
			commit = true;
		}
		finally {
			p.endTransaction(txID, commit);
		}
		return p;
	}

	private Program buildProgram2(String name) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._TOY_BE);
		Program p = builder.getProgram();
		builder.createMemory("text", "0x00402000", 0x100);
		builder.setBytes("0x00402000", "ff 8b 55 ec 8b c3");
		builder.disassemble("0x00402000", 6);
		Function function = builder.createFunction("0x00402000");
		int txID = p.startTransaction("Setting Function Name");
		boolean commit = false;
		try {
			function.setName("MyFunctionXY", SourceType.USER_DEFINED);
			commit = true;
		}
		finally {
			p.endTransaction(txID, commit);
		}
		return p;
	}

	private Program buildProgram3(String name) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._X64);
		Program p = builder.getProgram();
		// Make the instructions differ from program1 above so comments will have a NO_ADDRESS
		// for the destination address.
		builder.setBytes("0x00402000", "31 ed 49 89 d0 5e 48 89 e2 c3");
		builder.disassemble("0x00402000", 10);
		Function function = builder.createFunction("0x00402000");
		int txID = p.startTransaction("Setting Function Name");
		boolean commit = false;
		try {
			function.setName("MyFunctionZZ", SourceType.USER_DEFINED);
			commit = true;
		}
		finally {
			p.endTransaction(txID, commit);
		}
		return p;
	}

	private void createSession(String testSourceProgramName, String testDestinationProgramName)
			throws Exception {
		session = vtTestEnv.createSession(testSourceProgramName, testDestinationProgramName);
		initSession();
	}

	private void createSession(Program testSourceProgram, Program testDestinationProgram)
			throws Exception {
		session = vtTestEnv.createSession(testSourceProgram, testDestinationProgram);
		initSession();
	}

	private void initSession() {
		sourceProgram = vtTestEnv.getSourceProgram();
		disableAutoAnalysis(sourceProgram);

		destinationProgram = vtTestEnv.getDestinationProgram();
		disableAutoAnalysis(destinationProgram);

		controller = vtTestEnv.getVTController();
	}

	/**
	 * Establishes a program correlation within version tracking to be used by the test
	 * when creating matches.
	 * @param correlatorFactory the factory for the desired program correlator.
	 */
	protected void addProgramCorrelation(VTProgramCorrelatorFactory correlatorFactory) {
		try {
			correlator =
				vtTestEnv.correlate(correlatorFactory, null, TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
			e.printStackTrace();
		}
	}

	private void disableAutoAnalysis(Program program) {
		// we must cheat to do this since this is not intended
		// to be used outside of the analysis thread
		setInstanceField("ignoreChanges", AutoAnalysisManager.getAnalysisManager(program),
			Boolean.TRUE);
	}

	/**
	 * Checks the address correlation being used for the current testMatch and its current
	 * sourceFunction and destinationFunction to verify it is the one indicated by the 
	 * addressCorrelationName.
	 * @param addressCorrelationName the name of the expected address correlation for determining
	 * the destination address of markup for the current function match.
	 */
	private void checkAddressCorrelation(String addressCorrelationName) {
		AddressCorrelation actualCorrelator =
			controller.getCorrelator(sourceFunction, destinationFunction);
		String actualCorrelatorName = actualCorrelator.getName();
		assertTrue("Unexpected address correlation of " + actualCorrelatorName +
			" when expecting " + addressCorrelationName + ".",
			actualCorrelatorName.equals(addressCorrelationName));
	}

	/**
	 * Checks all the markup items for the testMatch to see that their destination address
	 * has been determined by the address correlation that is indicated by the addressCorrelationName
	 * or was set to the function entry point.
	 * @param addressCorrelationName the name of the expected address correlation for determining
	 * the destination address of non-function entry point markup items.
	 */
	private void checkMarkupDestinationSource(String addressCorrelationName,
			boolean canBeNoAddress) {
		Collection<VTMarkupItem> appliableMarkupItems =
			controller.getMatchInfo(testMatch).getAppliableMarkupItems(TaskMonitor.DUMMY); // Initialize the cache.
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			Address markupDestAddress = vtMarkupItem.getDestinationAddress();
			boolean isNoAddress =
				markupDestAddress == null || markupDestAddress == Address.NO_ADDRESS;
			if (isNoAddress) {
				assertTrue("Unexpected destination address of NO_ADDRESS for " +
					vtMarkupItem.getMarkupType().getDisplayName() + " markup @ " +
					vtMarkupItem.getSourceAddress().toString() + ".", canBeNoAddress);
				continue;
			}
			String destinationAddressSource = vtMarkupItem.getDestinationAddressSource();
			boolean isExpectedAddressCorrelation =
				addressCorrelationName.equals(destinationAddressSource);
			boolean isFunctionCorrelation =
				VTMarkupItem.FUNCTION_ADDRESS_SOURCE.equals(destinationAddressSource);
			assertTrue("Unexpected destination address source of " + destinationAddressSource +
				" for " + vtMarkupItem.getMarkupType().getDisplayName() + " markup @ " +
				vtMarkupItem.getSourceAddress().toString() + ".",
				(isExpectedAddressCorrelation || isFunctionCorrelation));
		}
	}

	/**
	 * Gets the match for the association indicated by the source and destination address.
	 * @param source the source address
	 * @param destination the destination address
	 * @return the match or null if the indicated match isn't found.
	 */
	protected VTMatch getMatch(Address source, Address destination) {
		List<VTMatchSet> matchSets = session.getMatchSets();
		// Get matchSet 2 since 0 is manual matches and 1 is implied matches.
		VTMatchSet vtMatchSet = matchSets.get(2);
		assertNotNull(vtMatchSet);
		Collection<VTMatch> matches = vtMatchSet.getMatches(source, destination);
		VTMatch[] matchesArray = matches.toArray(new VTMatch[matches.size()]);
		assertTrue(matchesArray.length > 0);
		VTMatch vtMatch = matchesArray[0];
		waitForSwing();
		return vtMatch;
	}

	/**
	 * Establishes the indicated match as the one being used in the test.
	 * @param sourceAddressString the source address of the match's association.
	 * @param destinationAddressString the destination address of the match's association.
	 */
	protected void useMatch(String sourceAddressString, String destinationAddressString) {
		sourceAddress = addr(sourceAddressString, sourceProgram);
		destinationAddress = addr(destinationAddressString, destinationProgram);

		testMatch = getMatch(sourceAddress, destinationAddress);
		assertNotNull(testMatch);

		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		assertNotNull(sourceFunction);
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		assertNotNull(destinationFunction);
	}

	/**
	 * Adds a comment of the indicated type at the specified address.
	 * @param commentType the comment type as defined in the CodeUnit class.
	 * @param sourceAddressString the source address of the markup
	 * @param comment the comment to be added at the source address
	 */
	private void addComment(int commentType, String sourceAddressString, String comment) {
		Address srcAddress = addr(sourceAddressString, sourceProgram);
		int txID = sourceProgram.startTransaction("Add Comment");
		boolean commit = false;
		try {
			Listing listing = sourceProgram.getListing();
			CodeUnit cu = listing.getCodeUnitAt(srcAddress);
			cu.setComment(commentType, comment);
			commit = true;
		}
		finally {
			sourceProgram.endTransaction(txID, commit);
		}
	}

	/**
	 * Check that the expected comment markup was created and it has the expected destination address.
	 * @param desiredCommentMarkupType the comment markup type we are checking
	 * @param sourceAddressString the source address of the markup
	 * @param comment the expected comment
	 * @param destinationAddressString the expected destination address for the markup
	 */
	private void checkCommentMarkup(VTMarkupType desiredCommentMarkupType,
			String sourceAddressString, String comment, String destinationAddressString) {
		Address srcAddress = addr(sourceAddressString, sourceProgram);
		Address destAddress =
			destinationAddressString.equals("NO_ADDRESS") ? Address.NO_ADDRESS
					: addr(
						destinationAddressString, destinationProgram);

		Collection<VTMarkupItem> appliableMarkupItems =
			controller.getMatchInfo(testMatch).getAppliableMarkupItems(TaskMonitor.DUMMY); // Initialize the cache.

		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			VTMarkupType markupType = vtMarkupItem.getMarkupType();
			if (markupType != desiredCommentMarkupType) {
				continue; // Not the right markup type.
			}
			Address markupSrcAddress = vtMarkupItem.getSourceAddress();
			if (!markupSrcAddress.equals(srcAddress)) {
				continue; // Not the right source address.
			}

			// Check the comment.
			Stringable sourceValue = vtMarkupItem.getSourceValue();
			String displayString = sourceValue.getDisplayString();
			assertEquals(comment, displayString);

			// Check destination address
			Address markupDestAddress = vtMarkupItem.getDestinationAddress();
			if (markupDestAddress == null) {
				markupDestAddress = Address.NO_ADDRESS;
			}
			boolean isNoAddress =
				markupDestAddress == null || markupDestAddress == Address.NO_ADDRESS;
			if (destAddress == Address.NO_ADDRESS) {
				assertTrue("Unexpected destination address of NO_ADDRESS for " +
					vtMarkupItem.getMarkupType().getDisplayName() + " markup @ " +
					vtMarkupItem.getSourceAddress().toString() + ".", isNoAddress);
				return;
			}
			assertTrue("Unexpected destination address of " + markupDestAddress.toString() +
				" when expecting " + destAddress.toString() + " for " +
				vtMarkupItem.getMarkupType().getDisplayName() + " markup @ " +
				vtMarkupItem.getSourceAddress().toString() + ".",
				markupDestAddress.equals(destAddress));
			return;
		}
	}
}
