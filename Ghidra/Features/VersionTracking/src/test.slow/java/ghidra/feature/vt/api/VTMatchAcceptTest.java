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

import static ghidra.feature.vt.db.VTTestUtils.*;
import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.*;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.task.AcceptMatchTask;
import ghidra.feature.vt.gui.task.VtTask;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.test.*;
import ghidra.util.exception.InvalidInputException;

public class VTMatchAcceptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private VTController controller;
	private VTSessionDB session;
	private ProgramDB sourceProgram;
	private ProgramDB destinationProgram;
	private VTPlugin plugin;
	private Options options;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		ClassicSampleX86ProgramBuilder sourceBuilder = new ClassicSampleX86ProgramBuilder();
		sourceProgram = sourceBuilder.getProgram();

		ClassicSampleX86ProgramBuilder destinationBuilder = new ClassicSampleX86ProgramBuilder();
		destinationProgram = destinationBuilder.getProgram();

		tool = env.getTool();

		tool.addPlugin(VTPlugin.class.getName());
		plugin = getPlugin(tool, VTPlugin.class);
		controller = new VTControllerImpl(plugin);

		session = new VTSessionDB(testName.getMethodName() + " - Test Match Set Manager",
			sourceProgram, destinationProgram, this);

		runSwing(() -> controller.openVersionTrackingSession(session));

		options = controller.getOptions();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testAcceptWithApplyDataLabels() throws Exception {

		//
		// This test exposes a bug because the hook that runs when you apply data on accept was
		// exhibiting a side effect, causing the destination address to be set. When the hook was 
		// changed to not set the destination address, the accept task was not setting the 
		// destination address as it should.
		//

		options.setBoolean(VTOptionDefines.APPLY_DATA_NAME_ON_ACCEPT, true);

		Address sourceAddress = addr("0x0100808c", sourceProgram);
		Address destinationAddress = addr("0x0100808c", destinationProgram);

		// force known values for the test
		DataType sourceDataType = new DWordDataType();
		DataType destinationDataType1 = new StringDataType();
		DataType destinationDataType2 = new WordDataType();
		setData(sourceDataType, 4, sourceAddress, sourceProgram);
		setData(destinationDataType1, 2, destinationAddress, destinationProgram);
		setData(destinationDataType2, 2, destinationAddress.add(2), destinationProgram);
		addLabel("Bob", sourceAddress, sourceProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, sourceAddress, destinationAddress);
		AcceptMatchTask task = new AcceptMatchTask(controller, Arrays.asList(match));
		runTask(task);

		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		assertEquals("Bob",
			destinationProgram.getSymbolTable().getPrimarySymbol(destinationAddress).getName());
	}

	private Symbol addLabel(String name, Address address, Program program)
			throws InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Label");
			return symbolTable.createLabel(address, name, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void runTask(VtTask task) {
		controller.runVTTask(task);
		waitForProgram(destinationProgram);
	}

	private Data setData(DataType dataType, int dtLength, Address address, Program program)
			throws CodeUnitInsertionException {

		Listing listing = program.getListing();
		Data data = null;
		boolean commit = false;
		int transaction = program.startTransaction("Test - Set Data");
		try {
			data = listing.createData(address, dataType, dtLength);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return data;
	}
}
