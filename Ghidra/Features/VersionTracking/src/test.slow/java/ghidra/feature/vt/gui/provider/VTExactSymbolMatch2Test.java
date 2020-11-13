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

import static ghidra.feature.vt.db.VTTestUtils.*;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.*;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.feature.vt.api.correlator.program.SymbolNameProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Tests to verify that the Exact Symbol Name program correlation determines matches as expected. 
 * This correlator should match on all labels at the entry point of the function or all labels at 
 * the minimum address for data.
 */
public class VTExactSymbolMatch2Test extends AbstractGhidraHeadedIntegrationTest {

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

	/////////////// Function Match Tests ///////////////

	@Test
	public void testFunction_NoMatch_Defaults() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		verifyNoFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("FUN_00411e70", "FUN_00411e50");

		//@formatter:off
		checkAllSymbols(
			new String[] {"FUN_00411e70"}, 
			new String[] {"FUN_00411e50"});
		//@formatter:on
	}

	@Test
	public void testFunction_NoMatch_SourceNamed() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbolOne");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		verifyNoFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("TestSymbolOne", "FUN_00411e50");

		//@formatter:off
		checkAllSymbols(
			new String[] {"TestSymbolOne"}, 
			new String[] {"FUN_00411e50"});
		//@formatter:on
	}

	@Test
	public void testFunction_NoMatch_DestNamed() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbolTwo");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		verifyNoFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("FUN_00411e70", "TestSymbolTwo");

		//@formatter:off
		checkAllSymbols(
			new String[] {"FUN_00411e70"}, 
			new String[] {"TestSymbolTwo"});
		//@formatter:on
	}

	@Test
	public void testFunction_Match_BothPrimary() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbol");
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbol");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("TestSymbol", "TestSymbol");

		//@formatter:off
		checkAllSymbols(
			new String[] {"TestSymbol"}, 
			new String[] {"TestSymbol"});
		//@formatter:on
	}

	@Test
	public void testFunction_Match_BothPrimary_endWith_underscore_addr() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbol_00411e70");
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbol_00411e50");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("TestSymbol_00411e70", "TestSymbol_00411e50");

		//@formatter:off
		checkAllSymbols(
			new String[] {"TestSymbol_00411e70"}, 
			new String[] {"TestSymbol_00411e50"});
		//@formatter:on
	}

	@Test
	public void testFunction_Match_BothPrimary_endWith_at_addr() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbol@00411e70");
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbol@00411e50");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("TestSymbol@00411e70", "TestSymbol@00411e50");

		//@formatter:off
		checkAllSymbols(
			new String[] {"TestSymbol@00411e70"}, 
			new String[] {"TestSymbol@00411e50"});
		//@formatter:on
	}

	@Test
	public void testFunction_Match_BothPrimary_endWith_one_of_each_addr() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbol_00411e70");
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbol@00411e50");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("TestSymbol_00411e70", "TestSymbol@00411e50");

		//@formatter:off
		checkAllSymbols(
			new String[] {"TestSymbol_00411e70"}, 
			new String[] {"TestSymbol@00411e50"});
		//@formatter:on
	}

	@Test
	public void testFunction_Match_SourceNotPrimary() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbol");
		addPrimarySymbol(sourceProgram, "0x00411e70", "Foo");
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbol");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("Foo", "TestSymbol");

		//@formatter:off
		checkAllSymbols(
			new String[] {"Foo", "TestSymbol"}, 
			new String[] {"TestSymbol"});
		//@formatter:on
	}

	@Test
	public void testFunction_Match_DestinationNotPrimary() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbol");
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbol");
		addPrimarySymbol(destinationProgram, "0x00411e50", "Foo");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("TestSymbol", "Foo");

		//@formatter:off
		checkAllSymbols(
			new String[] {"TestSymbol"}, 
			new String[] {"Foo", "TestSymbol"});
		//@formatter:on
	}

	@Test
	public void testFunction_Match_NeitherPrimary() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbol");
		addPrimarySymbol(sourceProgram, "0x00411e70", "Bar");
		addPrimarySymbol(sourceProgram, "0x00411e70", "Bat");
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbol");
		addPrimarySymbol(destinationProgram, "0x00411e50", "Foo");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("Bat", "Foo");

		//@formatter:off
		checkAllSymbols(
			new String[] {"Bar", "Bat", "TestSymbol"}, 
			new String[] {"Foo", "TestSymbol"});
		//@formatter:on
	}

	@Test
	public void testFunction_Match_TwoSameNames_OneMatch() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00411e70", "TestSymbol");
		addPrimarySymbol(sourceProgram, "0x00411e70", "Bar");
		addPrimarySymbol(sourceProgram, "0x00411e70", "Foo");
		addPrimarySymbol(sourceProgram, "0x00411e70", "Bat");
		addPrimarySymbol(destinationProgram, "0x00411e50", "TestSymbol");
		addPrimarySymbol(destinationProgram, "0x00411e50", "Foo");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useFunctionMatch("0x00411e70", "0x00411e50");
		checkPrimarySymbols("Bat", "Foo");

		//@formatter:off
		checkAllSymbols(
			new String[] {"Bar", "Bat", "Foo", "TestSymbol"}, 
			new String[] {"Foo", "TestSymbol"});
		//@formatter:on
	}

	/////////////// External Function Match Tests ///////////////

	@Test
	public void testExternalFunction_Match() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		Symbol sourceSymbol = getExternalSymbol(sourceProgram, "printf");
		assertNotNull(sourceSymbol);
		sourceAddress = sourceSymbol.getAddress();
		assertTrue(sourceAddress.isExternalAddress());
		Symbol destinationSymbol = getExternalSymbol(destinationProgram, "printf");
		assertNotNull(destinationSymbol);
		destinationAddress = destinationSymbol.getAddress();
		assertTrue(destinationAddress.isExternalAddress());
		testMatch = getMatch(sourceAddress, destinationAddress);
		assertNotNull(testMatch);
		assertEquals(VTAssociationType.FUNCTION, testMatch.getAssociation().getType());

		checkPrimarySymbols("printf", "printf");

		//@formatter:off
		checkAllSymbols(
			new String[] {"printf"}, 
			new String[] {"printf"});
		//@formatter:on
	}

	/////////////// Data Match Tests ///////////////

	@Test
	public void testData_NoMatch() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00416860", "foo");
		addPrimarySymbol(destinationProgram, "0x00416860", "bar");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		verifyNoDataMatch("0x00416860", "0x00416860");
		checkPrimarySymbols("foo", "bar");

		//@formatter:off
		checkAllSymbols(
			new String[] {"foo"}, 
			new String[] {"bar"});
		//@formatter:on
	}

	@Test
	public void testData_Match_DefaultLabelMatch() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useDataMatch("0x00416860", "0x00416860");
		checkPrimarySymbols("s_Wallace_00416860", "s_Wallace_00416860");

		//@formatter:off
		checkAllSymbols(
			new String[] {"s_Wallace_00416860"}, 
			new String[] {"s_Wallace_00416860"});
		//@formatter:on
	}

	@Test
	public void testData_Match_PrimaryMatch() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00416860", "DataSymbol");
		addPrimarySymbol(destinationProgram, "0x00416860", "DataSymbol");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useDataMatch("0x00416860", "0x00416860");
		checkPrimarySymbols("DataSymbol", "DataSymbol");

		//@formatter:off
		checkAllSymbols(
			new String[] {"DataSymbol"}, 
			new String[] {"DataSymbol"});
		//@formatter:on
	}

	@Test
	public void testData_Match_NonPrimaryMatch() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00416860", "DataSymbol");
		addPrimarySymbol(sourceProgram, "0x00416860", "Foo");
		addPrimarySymbol(destinationProgram, "0x00416860", "DataSymbol");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useDataMatch("0x00416860", "0x00416860");
		checkPrimarySymbols("Foo", "DataSymbol");

		//@formatter:off
		checkAllSymbols(
			new String[] {"DataSymbol", "Foo"}, 
			new String[] {"DataSymbol"});
		//@formatter:on
	}

	@Test
	public void testData_Match_TwoMatch() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00416860", "Bar");
		addPrimarySymbol(sourceProgram, "0x00416860", "Foo");
		addPrimarySymbol(destinationProgram, "0x00416860", "Bar");
		addPrimarySymbol(destinationProgram, "0x00416860", "Foo");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useDataMatch("0x00416860", "0x00416860");
		checkPrimarySymbols("Foo", "Foo");

		//@formatter:off
		checkAllSymbols(
			new String[] {"Bar", "Foo"}, 
			new String[] {"Bar", "Foo"});
		//@formatter:on
	}

	@Test
	public void testData_Match_OtherTwoMatch() throws Exception {
		createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		vtTestEnv.showTool();
		addPrimarySymbol(sourceProgram, "0x00416860", "Bar");
		addPrimarySymbol(sourceProgram, "0x00416860", "Foo");
		addPrimarySymbol(sourceProgram, "0x00416860", "A");
		addPrimarySymbol(destinationProgram, "0x00416860", "Foo");
		addPrimarySymbol(destinationProgram, "0x00416860", "Bar");
		addPrimarySymbol(destinationProgram, "0x00416860", "B");

		addProgramCorrelation(new SymbolNameProgramCorrelatorFactory());
		useDataMatch("0x00416860", "0x00416860");
		checkPrimarySymbols("A", "B");

		//@formatter:off
		checkAllSymbols(
			new String[] {"A", "Bar", "Foo"}, 
			new String[] {"B", "Bar", "Foo"});
		//@formatter:on
	}

//==================================================================================================
// Helper Methods
//==================================================================================================	

	private Symbol getExternalSymbol(Program program, String name) {
		SymbolTable sourceSymbolTable = program.getSymbolTable();
		SymbolIterator externalSymbols = sourceSymbolTable.getExternalSymbols();
		for (Symbol symbol : externalSymbols) {
			if (symbol.getName().equals(name)) {
				return symbol;
			}
		}
		return null;
	}

	private void createSession(String testSourceProgramName, String testDestinationProgramName)
			throws Exception {
		session = vtTestEnv.createSession(testSourceProgramName, testDestinationProgramName);
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
		if (matches.isEmpty()) {
			return null;
		}
		VTMatch[] matchesArray = matches.toArray(new VTMatch[matches.size()]);
		assertEquals(1, matchesArray.length);
		VTMatch vtMatch = matchesArray[0];
		waitForSwing();
		return vtMatch;
	}

	/**
	 * Determines that there are functions at the indicated source and destination,
	 * but no match was created.
	 * @param sourceAddressString the source address.
	 * @param destinationAddressString the destination address.
	 */
	protected void verifyNoFunctionMatch(String sourceAddressString,
			String destinationAddressString) {
		sourceAddress = addr(sourceAddressString, sourceProgram);
		destinationAddress = addr(destinationAddressString, destinationProgram);

		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		assertNotNull(sourceFunction);
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		assertNotNull(destinationFunction);

		testMatch = getMatch(sourceAddress, destinationAddress);
		assertNull(testMatch);
	}

	/**
	 * Establishes the indicated function match as the one being used in the test.
	 * @param sourceAddressString the source address of the match's association.
	 * @param destinationAddressString the destination address of the match's association.
	 */
	protected void useFunctionMatch(String sourceAddressString, String destinationAddressString) {
		sourceAddress = addr(sourceAddressString, sourceProgram);
		destinationAddress = addr(destinationAddressString, destinationProgram);

		testMatch = getMatch(sourceAddress, destinationAddress);
		assertNotNull(testMatch);
		assertEquals(VTAssociationType.FUNCTION, testMatch.getAssociation().getType());

		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		assertNotNull(sourceFunction);
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		assertNotNull(destinationFunction);
	}

	/**
	 * Determines that there are data at the indicated source and destination,
	 * but no match was created.
	 * @param sourceAddressString the source address.
	 * @param destinationAddressString the destination address.
	 */
	protected void verifyNoDataMatch(String sourceAddressString, String destinationAddressString) {
		sourceAddress = addr(sourceAddressString, sourceProgram);
		destinationAddress = addr(destinationAddressString, destinationProgram);

		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		assertNull(sourceFunction);
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		assertNull(destinationFunction);

		Data sourceData = sourceProgram.getListing().getDataAt(sourceAddress);
		assertNotNull(sourceData);
		Data destinationData = destinationProgram.getListing().getDataAt(destinationAddress);
		assertNotNull(destinationData);

		testMatch = getMatch(sourceAddress, destinationAddress);
		assertNull(testMatch);
	}

	/**
	 * Establishes the indicated data match as the one being used in the test.
	 * @param sourceAddressString the source address of the match's association.
	 * @param destinationAddressString the destination address of the match's association.
	 */
	protected void useDataMatch(String sourceAddressString, String destinationAddressString) {
		sourceAddress = addr(sourceAddressString, sourceProgram);
		destinationAddress = addr(destinationAddressString, destinationProgram);

		testMatch = getMatch(sourceAddress, destinationAddress);
		assertNotNull(testMatch);
		assertEquals(VTAssociationType.DATA, testMatch.getAssociation().getType());

		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		assertNull(sourceFunction);
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		assertNull(destinationFunction);

		Data sourceData = sourceProgram.getListing().getDataAt(sourceAddress);
		assertNotNull(sourceData);
		Data destinationData = destinationProgram.getListing().getDataAt(destinationAddress);
		assertNotNull(destinationData);
	}

	/**
	 * Adds a symbol with the indicated name at the specified address and makes it primary.
	 * @param program the program containing the symbol
	 * @param addressString the source address of the markup
	 * @param symbolName the name of the symbol being added
	 * @throws DuplicateNameException if the name exists
	 * @throws InvalidInputException if name is invalid
	 */
	private void addPrimarySymbol(Program program, String addressString, String symbolName)
			throws DuplicateNameException, InvalidInputException {
		Address address = addr(addressString, program);
		int txID = program.startTransaction("Add Primary Symbol");
		boolean commit = false;
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			Symbol symbol = symbolTable.createLabel(address, symbolName, SourceType.USER_DEFINED);
			SetLabelPrimaryCmd setLabelPrimaryCmd =
				new SetLabelPrimaryCmd(address, symbol.getName(), symbol.getParentNamespace());
			vtTestEnv.getTool().execute(setLabelPrimaryCmd, program);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}
	}

	private void checkPrimarySymbols(String sourcePrimary, String destPrimary) {
		Symbol sourceSymbol = sourceProgram.getSymbolTable().getPrimarySymbol(sourceAddress);
		Symbol destSymbol =
			destinationProgram.getSymbolTable().getPrimarySymbol(destinationAddress);
		assertEquals(sourcePrimary, sourceSymbol.getName());
		assertEquals(destPrimary, destSymbol.getName());
	}

	private void checkAllSymbols(String[] expectedSourceSymbols, String[] expectedDestSymbols) {
		Arrays.sort(expectedSourceSymbols);
		Arrays.sort(expectedDestSymbols);
		String[] actualSourceSymbols =
			convertSymbolsToNames(sourceProgram.getSymbolTable().getSymbols(sourceAddress));
		String[] actualDestSymbols =
			convertSymbolsToNames(
				destinationProgram.getSymbolTable().getSymbols(destinationAddress));

		Arrays.sort(actualSourceSymbols);
		Arrays.sort(actualDestSymbols);
		//@formatter:off
		assertTrue("Source Expected: " + Arrays.toString(expectedSourceSymbols) + "    Actual: " +
			Arrays.toString(actualSourceSymbols),
			Arrays.equals(expectedSourceSymbols, actualSourceSymbols));
		assertTrue("Dest Expected: " + Arrays.toString(expectedDestSymbols) + "    Actual: " +
			Arrays.toString(actualDestSymbols),
			Arrays.equals(expectedDestSymbols, actualDestSymbols));
		//@formatter:on
	}

	private String[] convertSymbolsToNames(Symbol[] symbols) {
		String[] names = new String[symbols.length];
		int i = 0;
		for (Symbol symbol : symbols) {
			names[i++] = symbol.getName();
		}
		return names;
	}
}
