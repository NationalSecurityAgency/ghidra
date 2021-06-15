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

import static org.junit.Assert.*;

import java.util.List;

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.wizard.WizardManager;
import docking.wizard.WizardPanel;
import generic.test.TestUtils;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.AddressInput;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.wizard.*;
import ghidra.feature.vt.gui.wizard.ChooseAddressSetEditorPanel.AddressSetChoice;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.SystemUtilities;
import ghidra.util.table.GhidraTable;

public class VTAddToSessionTest extends AbstractGhidraHeadedIntegrationTest {

	private static String TEST_SOURCE_PROGRAM_NAME = "VersionTracking/WallaceSrc";
	private static String TEST_DESTINATION_PROGRAM_NAME = "VersionTracking/WallaceVersion2";

	private enum VTWizardPanelAction {
		BACK, NEXT, FINISH, CANCEL;
	}

	private TestEnv env;
	private PluginTool tool;
	private VTPlugin plugin;
	private VTController controller;
	private ProgramDB sourceProgram;
	private ProgramDB destinationProgram;
	private VTSessionDB session;
	private VTAddToSessionWizardManager vtWizardManager;
	private WizardManager wizardManager;
	private AddressSet sourceSelection;
	private AddressSet destinationSelection;

	public VTAddToSessionTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		setErrorGUIEnabled(false);
		env = new TestEnv();
		sourceProgram = env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = env.getProgram(TEST_DESTINATION_PROGRAM_NAME);
		tool = env.getTool();

		sourceSelection = new AddressSet();

		// Gadget::Gadget
		sourceSelection.addRange(sourceAddress("00411440"), sourceAddress("00411491"));

		// Gadget::use
		sourceSelection.addRange(sourceAddress("00411570"), sourceAddress("004115b8"));

		// Gadget::print
		sourceSelection.addRange(sourceAddress("004115d0"), sourceAddress("00411684"));
		destinationSelection = new AddressSet();

		// Gadget::Gadget
		destinationSelection.addRange(destinationAddress("00411430"),
			destinationAddress("0041149f"));

		// Gadget::print
		destinationSelection.addRange(destinationAddress("004115c0"),
			destinationAddress("004116af"));

		tool.addPlugin(VTPlugin.class.getName());
		plugin = getPlugin(tool, VTPlugin.class);
		env.showTool();
		controller = plugin.getController();
	}

	@After
	public void tearDown() throws Exception {
		if (sourceProgram != null) {
			env.release(sourceProgram);
		}
		if (destinationProgram != null) {
			env.release(destinationProgram);
		}
		env.dispose();
	}

	@Test
	public void testAddToSessionNoSelectionUnlimitedAddresses() throws Exception {

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Exact Function Instructions Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, false);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, false, VTWizardPanelAction.NEXT);

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Exact Function Instructions Match<br>" + "No<br>" + "Entire Source Program<br>" +
			"Entire Destination Program<br>" + "</html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 47, vtMatchSet2.getMatchCount());
	}

	@Test
	public void testAddToSessionNoSelectionLimitAddressesToEntireProgram() throws Exception {

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Exact Function Instructions Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, false);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, true, VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		checkAddressSetChoices(AddressSetChoice.ENTIRE_PROGRAM, AddressSetChoice.ENTIRE_PROGRAM);
		checkAddressSets(sourceProgram.getMemory(), destinationProgram.getMemory());
		changeAddressSetsPanel(AddressSetChoice.ENTIRE_PROGRAM, AddressSetChoice.ENTIRE_PROGRAM,
			VTWizardPanelAction.NEXT);

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Exact Function Instructions Match<br>" + "No<br>" + "Entire Source Program<br>" +
			"Entire Destination Program<br>" + "</html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 47, vtMatchSet2.getMatchCount());
	}

	@Test
	public void testAddToSessionNoSelectionLimitAddressesToMyOwn() throws Exception {

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Exact Function Instructions Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, false);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, true, VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		checkAddressSetChoices(AddressSetChoice.ENTIRE_PROGRAM, AddressSetChoice.ENTIRE_PROGRAM);
		checkAddressSets(sourceProgram.getMemory(), destinationProgram.getMemory());
		changeAddressSetsPanel(AddressSetChoice.MANUALLY_DEFINED, AddressSetChoice.MANUALLY_DEFINED,
			VTWizardPanelAction.NEXT);

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Exact Function Instructions Match<br>" + "No<br>" + "Manually Defined<br>" +
			"Manually Defined<br>" + "</html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 47, vtMatchSet2.getMatchCount());
	}

	@Test
	public void testAddToSessionNoSelectionLimitAddressesToMyOwnChanged() throws Exception {

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Exact Function Instructions Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, false);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, true, VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		checkAddressSetChoices(AddressSetChoice.ENTIRE_PROGRAM, AddressSetChoice.ENTIRE_PROGRAM);
		checkAddressSets(sourceProgram.getMemory(), destinationProgram.getMemory());

		// Specify manually defined address sets.
		changeAddressSetChoices(AddressSetChoice.MANUALLY_DEFINED,
			AddressSetChoice.MANUALLY_DEFINED);

		AddressSet desiredSourceSet = new AddressSet();
		desiredSourceSet.addRange(sourceAddress("00411440"), sourceAddress("004114af"));

		AddressSet desiredDestinationSet = new AddressSet();
		desiredDestinationSet.addRange(destinationAddress("00411430"),
			destinationAddress("0041149f"));

		changeAddressSets(desiredSourceSet, desiredDestinationSet);

		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.NEXT));

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Exact Function Instructions Match<br>" + "No<br>" + "Manually Defined<br>" +
			"Manually Defined<br>" + "</html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 1, vtMatchSet2.getMatchCount());
	}

	@Test
	public void testAddToSessionWithSelectionLimitAddressesToEntireProgram() throws Exception {

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createSelectionInSourceAndDestinationTools();

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Exact Function Instructions Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, true);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, true, VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		checkAddressSetChoices(AddressSetChoice.SELECTION, AddressSetChoice.SELECTION);
		checkAddressSets(sourceSelection, destinationSelection);
		changeAddressSetsPanel(AddressSetChoice.ENTIRE_PROGRAM, AddressSetChoice.ENTIRE_PROGRAM,
			VTWizardPanelAction.NEXT);

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Exact Function Instructions Match<br>" + "No<br>" + "Entire Source Program<br>" +
			"Entire Destination Program<br>" + "</html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 47, vtMatchSet2.getMatchCount());
	}

	@Test
	public void testAddToSessionWithSelectionLimitAddressesToSelection() throws Exception {

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createSelectionInSourceAndDestinationTools();

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Exact Function Instructions Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, true);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, true, VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		checkAddressSetChoices(AddressSetChoice.SELECTION, AddressSetChoice.SELECTION);
		checkAddressSets(sourceSelection, destinationSelection);
		changeAddressSetsPanel(AddressSetChoice.SELECTION, AddressSetChoice.SELECTION,
			VTWizardPanelAction.NEXT);

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Exact Function Instructions Match<br>No<br>Source Tool Selection<br>" +
			"Destination Tool Selection<br></html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 2, vtMatchSet2.getMatchCount());
	}

	@Test
	public void testAddToSessionWithSelectionLimitAddressesToMyOwn() throws Exception {

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createSelectionInSourceAndDestinationTools();

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Exact Function Instructions Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, true);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, true, VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		checkAddressSetChoices(AddressSetChoice.SELECTION, AddressSetChoice.SELECTION);
		checkAddressSets(sourceSelection, destinationSelection);

		// Specify manually defined address sets.
		changeAddressSetChoices(AddressSetChoice.MANUALLY_DEFINED,
			AddressSetChoice.MANUALLY_DEFINED);

		AddressSet desiredSourceSet = new AddressSet();
		desiredSourceSet.addRange(sourceAddress("00411440"), sourceAddress("004114af"));

		AddressSet desiredDestinationSet = new AddressSet();
		desiredDestinationSet.addRange(destinationAddress("00411430"),
			destinationAddress("0041149f"));

		changeAddressSets(desiredSourceSet, desiredDestinationSet);

		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.NEXT));

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Exact Function Instructions Match<br>" + "No<br>" + "Manually Defined<br>" +
			"Manually Defined<br>" + "</html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 1, vtMatchSet2.getMatchCount());
	}

	@Test
	public void testAddToSessionWithSelectionLimitAddressesToMyOwnThenBackNext() throws Exception {

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createSelectionInSourceAndDestinationTools();

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Exact Function Instructions Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, true);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(true, true, VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		checkAddressSetChoices(AddressSetChoice.SELECTION, AddressSetChoice.SELECTION);

		// Specify manually defined address sets.
		changeAddressSetChoices(AddressSetChoice.MANUALLY_DEFINED,
			AddressSetChoice.MANUALLY_DEFINED);

		AddressSet desiredSourceSet = new AddressSet();
		desiredSourceSet.addRange(sourceAddress("00411440"), sourceAddress("004114af"));

		AddressSet desiredDestinationSet = new AddressSet();
		desiredDestinationSet.addRange(destinationAddress("00411430"),
			destinationAddress("0041149f"));

		changeAddressSets(desiredSourceSet, desiredDestinationSet);

		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.NEXT));

		// Check the summary panel and then begin going back through wizard panels.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Exact Function Instructions Match<br>" + "Yes<br>" + "Manually Defined<br>" +
			"Manually Defined<br>" + "</html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.BACK);

		checkAddressSetChoices(AddressSetChoice.MANUALLY_DEFINED,
			AddressSetChoice.MANUALLY_DEFINED);
		checkAddressSets(desiredSourceSet, desiredDestinationSet);
		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.BACK));

		checkAddressSetOptionsPanel(true, true);
		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.BACK));

		// Go back to correlator choice panel.
		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.BACK));

		// Go to correlator options panel.
		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.NEXT));

		// Go to address set options panel.
		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.NEXT));

		// Go to address sets panel.
		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.NEXT));

		// Go to summary panel.
		SystemUtilities.runSwingNow(() -> invoke(VTWizardPanelAction.NEXT));

		// Check summary panel again and then finish.
		checkWizardButtonEnablement(true, false, true, true);
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 1, vtMatchSet2.getMatchCount());
	}

	@Test
	public void testAddToSessionResultingInNoMatchesFound() throws Exception {

		setErrorGUIEnabled(true);
		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		String sessionName = "Untitled";

		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));

		assertNotNull(controller.getSourceProgram());
		assertNotNull(controller.getDestinationProgram());

		createWizardManager();

		runSwingLater(
			() -> wizardManager.showWizard(controller.getParentComponent()));

		waitForDialogComponent(WizardManager.class);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel("Data Reference Match", VTWizardPanelAction.NEXT);

		checkWizardButtonEnablement(true, true, true, true);
		changeCorrelatorOptionsPanel(null, VTWizardPanelAction.NEXT);

		checkAddressSetOptionsPanel(false, false);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, false, VTWizardPanelAction.NEXT);

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" + sessionName +
			"<br>" + TEST_SOURCE_PROGRAM_NAME + "<br>" + TEST_DESTINATION_PROGRAM_NAME + "<br>" +
			"Data Reference Match<br>" + "No<br>" + "Entire Source Program<br>" +
			"Entire Destination Program<br>" + "</html>";
		checkSummaryPanel(labelString, summaryString, VTWizardPanelAction.FINISH);

		String msgStart = "No matches were found by the following program correlators";
		String msgContains = "Data Reference Match";
		JDialog dialog = waitForJDialog("Version Tracking: Add To Session");
		assertNotNull("Info dialog not found", dialog);

		String message = getMessageText(dialog);
		assertTrue("Expected Server Error message starting with: " + msgStart,
			message.startsWith(msgStart));
		assertTrue("Expected Server Error message containing: " + msgContains,
			message.contains(msgContains));
		pressButtonByText(dialog, "OK");
		waitForSwing();

		// Check that the expected matches were added to the session.
		List<VTMatchSet> matchSets = session.getMatchSets();
		int size = matchSets.size();
		assertEquals(3, size);
		VTMatchSet vtMatchSet0 = matchSets.get(0);// Reserved for Manual Matches
		assertNotNull(vtMatchSet0);
		VTMatchSet vtMatchSet1 = matchSets.get(1);// Reserved for Implied Matches
		assertNotNull(vtMatchSet1);
		VTMatchSet vtMatchSet2 = matchSets.get(2);// The correlation run's matches
		assertNotNull(vtMatchSet2);
		assertEquals("Number of matches", 0, vtMatchSet2.getMatchCount());
	}

	private void chooseFromCorrelationPanel(String correlatorName,
			VTWizardPanelAction wizardAction) {

		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof CorrelatorPanel);
		CorrelatorPanel correlatorPanel = (CorrelatorPanel) currentWizardPanel;
		SystemUtilities.runSwingNow(() -> {
			GhidraTable table = (GhidraTable) TestUtils.getInstanceField("table", correlatorPanel);
			TableModel model = table.getModel();
			int column = getNamedColumnIndex("Name", model);
			assertTrue(column >= 0);
			int row = getRowWithFieldValueInColumn(correlatorName, model, column);
			assertTrue(row >= 0);
			model.setValueAt(Boolean.TRUE, row, 0);
			invoke(wizardAction);
		});
	}

	private void changeCorrelatorOptionsPanel(Object correlatorOptionsObject,
			VTWizardPanelAction wizardAction) {

		// Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof OptionsPanel);
		// Nothing else to check in this panel for now.

		// TODO Use an OptionsObject or something to pass in correlator options and set them in the panel.
//		// get out the correlator options
//		AddressCorrelatorManager correlator = controller.getCorrelator();
//		assertNotNull("The controller did not find any correlators", correlator);
//
//		// set some options settings
//		Options options = correlator.getOptions(LCSAddressCorrelator.class);
//		String testDefaultValue = "Test Default Value";
//		String testOptionKey = "Test Option Name";
//		String value = options.getString(testOptionKey, testDefaultValue);
//		assertEquals(value, testDefaultValue);
//
//		String firstNewOptionValue = "New Option Value";
//		options.putString(testOptionKey, firstNewOptionValue);
//		assertEquals(firstNewOptionValue, options.getString(testOptionKey, null));
//		correlator.setOptions(LCSAddressCorrelator.class, options);
//		// save the options 
//		SaveState saveState = new SaveState();
//		controller.writeConfigState(saveState);
//
//		// change the options
//		String secondNewValue = "Second New Value";
//		options.putString(testOptionKey, secondNewValue);
//		correlator.setOptions(LCSAddressCorrelator.class, options);
//
//		// pull the values again and make sure they are still correct (that writing the config
//		// state did not change the cached controller and options) 
//		correlator = controller.getCorrelator();
//		options = correlator.getOptions(LCSAddressCorrelator.class);
//		assertEquals(secondNewValue, options.getString(testOptionKey, null));

		SystemUtilities.runSwingNow(() -> invoke(wizardAction));
	}

	private void checkAddressSetOptionsPanel(boolean excludeAccepted, boolean limitAddressSets) {

		// Address Set Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof AddressSetOptionsPanel);
		AddressSetOptionsPanel addressSetOptionsPanel = (AddressSetOptionsPanel) currentWizardPanel;

		JCheckBox excludeCheckbox =
			(JCheckBox) TestUtils.getInstanceField("excludeCheckbox", addressSetOptionsPanel);
		assertNotNull(excludeCheckbox);

		JCheckBox showAddressSetPanelsCheckbox =
			(JCheckBox) TestUtils.getInstanceField("showAddressSetPanelsCheckbox",
				addressSetOptionsPanel);
		assertNotNull(showAddressSetPanelsCheckbox);

		assertEquals("Exclude Accepted Matches checkbox", excludeAccepted,
			excludeCheckbox.isSelected());
		assertEquals("Limit Address Sets checkbox", limitAddressSets,
			showAddressSetPanelsCheckbox.isSelected());
	}

	private void changeAddressSetOptionsPanel(boolean excludeAccepted, boolean limitAddressSets,
			VTWizardPanelAction wizardAction) {

		// Address Set Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof AddressSetOptionsPanel);
		AddressSetOptionsPanel addressSetOptionsPanel = (AddressSetOptionsPanel) currentWizardPanel;

		JCheckBox excludeCheckbox =
			(JCheckBox) TestUtils.getInstanceField("excludeCheckbox", addressSetOptionsPanel);
		assertNotNull(excludeCheckbox);

		JCheckBox showAddressSetPanelsCheckbox =
			(JCheckBox) TestUtils.getInstanceField("showAddressSetPanelsCheckbox",
				addressSetOptionsPanel);
		assertNotNull(showAddressSetPanelsCheckbox);

		if (excludeCheckbox.isSelected() != excludeAccepted) {
			excludeCheckbox.setSelected(excludeAccepted);
		}

		if (showAddressSetPanelsCheckbox.isSelected() != limitAddressSets) {
			showAddressSetPanelsCheckbox.setSelected(limitAddressSets);
		}

		SystemUtilities.runSwingNow(() -> invoke(wizardAction));
	}

	private void changeAddressSetChoices(AddressSetChoice sourceChoice,
			AddressSetChoice destinationChoice) {

		// Address Set Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof LimitAddressSetsPanel);
		LimitAddressSetsPanel limitAddressSetsPanel = (LimitAddressSetsPanel) currentWizardPanel;

		AddressSetPanel sourcePanel =
			(AddressSetPanel) TestUtils.getInstanceField("sourcePanel", limitAddressSetsPanel);
		assertNotNull(sourcePanel);

		AddressSetPanel destinationPanel =
			(AddressSetPanel) TestUtils.getInstanceField("destinationPanel", limitAddressSetsPanel);
		assertNotNull(destinationPanel);

		changeAddressChoice(sourcePanel, sourceChoice);
		changeAddressChoice(destinationPanel, destinationChoice);
	}

	private void checkAddressSets(AddressSetView desiredSourceSet,
			AddressSetView desiredDestinationSet) {

		// Address Set Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof LimitAddressSetsPanel);
		LimitAddressSetsPanel limitAddressSetsPanel = (LimitAddressSetsPanel) currentWizardPanel;

		AddressSetPanel sourcePanel =
			(AddressSetPanel) TestUtils.getInstanceField("sourcePanel", limitAddressSetsPanel);
		assertNotNull(sourcePanel);

		AddressSetPanel destinationPanel =
			(AddressSetPanel) TestUtils.getInstanceField("destinationPanel", limitAddressSetsPanel);
		assertNotNull(destinationPanel);

		ChooseAddressSetEditorPanel sourceSetPanel =
			(ChooseAddressSetEditorPanel) TestUtils.getInstanceField("panel", sourcePanel);
		assertNotNull(sourceSetPanel);

		ChooseAddressSetEditorPanel destinationSetPanel =
			(ChooseAddressSetEditorPanel) TestUtils.getInstanceField("panel", destinationPanel);
		assertNotNull(destinationSetPanel);

		AddressSetView panelSourceSet =
			(AddressSetView) TestUtils.invokeInstanceMethod("getAddressSetView", sourceSetPanel);
		AddressSetView panelDestinationSet =
			(AddressSetView) TestUtils.invokeInstanceMethod("getAddressSetView",
				destinationSetPanel);
		assertEquals("Source Address Set", desiredSourceSet, panelSourceSet);
		assertEquals("Destination Address Set", desiredDestinationSet, panelDestinationSet);
	}

	private void changeAddressSets(AddressSetView desiredSourceSet,
			AddressSetView desiredDestinationSet) {

		// Address Set Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof LimitAddressSetsPanel);
		LimitAddressSetsPanel limitAddressSetsPanel = (LimitAddressSetsPanel) currentWizardPanel;

		AddressSetPanel sourcePanel =
			(AddressSetPanel) TestUtils.getInstanceField("sourcePanel", limitAddressSetsPanel);
		assertNotNull(sourcePanel);

		AddressSetPanel destinationPanel =
			(AddressSetPanel) TestUtils.getInstanceField("destinationPanel", limitAddressSetsPanel);
		assertNotNull(destinationPanel);

		changeAddressSetViaListRemoveRange(true, sourcePanel, desiredSourceSet);
		changeAddressSetViaSubtractDialog(false, destinationPanel, desiredDestinationSet);
	}

	private void checkAddressSetChoices(AddressSetChoice sourceChoice,
			AddressSetChoice destinationChoice) {

		// Address Set Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof LimitAddressSetsPanel);
		LimitAddressSetsPanel limitAddressSetsPanel = (LimitAddressSetsPanel) currentWizardPanel;

		AddressSetPanel sourcePanel =
			(AddressSetPanel) TestUtils.getInstanceField("sourcePanel", limitAddressSetsPanel);
		assertNotNull(sourcePanel);

		AddressSetPanel destinationPanel =
			(AddressSetPanel) TestUtils.getInstanceField("destinationPanel", limitAddressSetsPanel);
		assertNotNull(destinationPanel);

		checkAddressChoice(sourcePanel, sourceChoice);
		checkAddressChoice(destinationPanel, destinationChoice);
	}

	private void checkAddressChoice(AddressSetPanel addressSetPanel,
			AddressSetChoice expectedChoice) {
		ChooseAddressSetEditorPanel panel =
			(ChooseAddressSetEditorPanel) TestUtils.getInstanceField("panel", addressSetPanel);
		assertNotNull(panel);
		AddressSetChoice addressSetChoice = panel.getAddressSetChoice();
		assertEquals(addressSetPanel.getName() + " Panel address set choice", expectedChoice,
			addressSetChoice);
	}

	private void changeAddressChoice(AddressSetPanel addressSetPanel,
			AddressSetChoice expectedChoice) {
		ChooseAddressSetEditorPanel panel =
			(ChooseAddressSetEditorPanel) TestUtils.getInstanceField("panel", addressSetPanel);
		assertNotNull(panel);
		AddressSetChoice addressSetChoice = panel.getAddressSetChoice();
		if (expectedChoice != addressSetChoice) {
			JRadioButton button = null;
			switch (expectedChoice) {
				case ENTIRE_PROGRAM:
					button =
						(JRadioButton) TestUtils.getInstanceField("entireProgramButton", panel);
					assertNotNull(panel);
					break;
				case SELECTION:
					button =
						(JRadioButton) TestUtils.getInstanceField("toolSelectionButton", panel);
					assertNotNull(panel);
					break;
				case MANUALLY_DEFINED:
					button = (JRadioButton) TestUtils.getInstanceField("myRangesButton", panel);
					assertNotNull(panel);
					break;
			}
			assertNotNull("Couldn't get button for choice of " + expectedChoice, button);
			pressButton(button);
			waitForButtonToSelect(button, 1000);
		}
	}

	private void changeAddressSetViaListRemoveRange(boolean isSource,
			AddressSetPanel addressSetPanel, AddressSetView desiredAddressSet) {
		ChooseAddressSetEditorPanel panel =
			(ChooseAddressSetEditorPanel) TestUtils.getInstanceField("panel", addressSetPanel);
		assertNotNull(panel);

		JButton addRangeButton =
			(JButton) TestUtils.getInstanceField("addRangeButton", panel);
		assertNotNull("Couldn't get button for adding address range.", addRangeButton);
		JButton listRemoveRangeButton =
			(JButton) TestUtils.getInstanceField("removeRangeButton", panel);
		assertNotNull("Couldn't get button for removing address range for list selection.",
			listRemoveRangeButton);
		JList<?> list = (JList<?>) TestUtils.getInstanceField("list", panel);
		SystemUtilities.runSwingNow(() -> {
			ListModel<?> model = list.getModel();
			int size = model.getSize();
			list.setSelectionInterval(0, size - 1);// Select all items in the list.
		});

		pressButton(listRemoveRangeButton);
		waitForSwing();

		AddressRangeIterator addressRanges = desiredAddressSet.getAddressRanges();
		for (AddressRange addressRange : addressRanges) {
			Runnable r = () -> addRangeButton.doClick();
			runSwing(r, false);
			enterAddressRange(isSource, "Add", addressRange);
		}
	}

	private void changeAddressSetViaSubtractDialog(boolean isSource,
			AddressSetPanel addressSetPanel, AddressSetView desiredAddressSet) {
		ChooseAddressSetEditorPanel panel =
			(ChooseAddressSetEditorPanel) TestUtils.getInstanceField("panel", addressSetPanel);
		assertNotNull(panel);

		JButton addRangeButton =
			(JButton) TestUtils.getInstanceField("addRangeButton", panel);
		JButton subtractRangeButton =
			(JButton) TestUtils.getInstanceField("subtractRangeButton", panel);

		Runnable r = () -> subtractRangeButton.doClick();
		runSwing(r, false);
		enterAddressRange(false, "Remove", "00000000", "ffffffff");

		AddressRangeIterator addressRanges = desiredAddressSet.getAddressRanges();
		for (AddressRange addressRange : addressRanges) {
			r = () -> addRangeButton.doClick();
			runSwing(r, false);
			enterAddressRange(isSource, "Add", addressRange);
		}
	}

	private void enterAddressRange(boolean isSource, String buttonText,
			String minAddress, String maxAddress) {

		AddRemoveAddressRangeDialog addRemoveDialog =
			waitForDialogComponent(AddRemoveAddressRangeDialog.class);
		assertNotNull(addRemoveDialog);
		waitForSwing();

		// Check dialog title.
		assertEquals((isSource ? "Source" : "Destination") + " Address Range",
			addRemoveDialog.getTitle());

		AddressInput minAddressField =
			(AddressInput) TestUtils.getInstanceField("minAddressField", addRemoveDialog);
		assertNotNull(minAddressField);

		runSwingLater(() -> {
			Address address = isSource ? sourceAddress(minAddress) : destinationAddress(minAddress);
			minAddressField.setAddress(address);
		});
		waitForSwing();

		AddressInput maxAddressField =
			(AddressInput) TestUtils.getInstanceField("maxAddressField", addRemoveDialog);
		assertNotNull(maxAddressField);
		runSwingLater(() -> {
			Address address = isSource ? sourceAddress(maxAddress) : destinationAddress(maxAddress);
			maxAddressField.setAddress(address);
		});
		waitForSwing();

		pressButtonByText(addRemoveDialog.getComponent(), buttonText);

		assertTrue("Dialog not closed after pressing: " + buttonText, !addRemoveDialog.isShowing());
	}

	private void enterAddressRange(boolean isSource, String buttonText,
			Address minAddress, Address maxAddress) {

		AddRemoveAddressRangeDialog addRemoveDialog =
			waitForDialogComponent(AddRemoveAddressRangeDialog.class);
		assertNotNull(addRemoveDialog);
		waitForSwing();

		// Check dialog title.
		assertEquals((isSource ? "Source" : "Destination") + " Address Range",
			addRemoveDialog.getTitle());

		AddressInput minAddressField =
			(AddressInput) TestUtils.getInstanceField("minAddressField", addRemoveDialog);
		assertNotNull(minAddressField);

		runSwingLater(() -> minAddressField.setAddress(minAddress));

		waitForSwing();

		AddressInput maxAddressField =
			(AddressInput) TestUtils.getInstanceField("maxAddressField", addRemoveDialog);
		assertNotNull(maxAddressField);
		runSwingLater(() -> {
			maxAddressField.setAddress(maxAddress);
		});

		waitForSwing();

		pressButtonByText(addRemoveDialog.getComponent(), buttonText);

		assertTrue("Dialog not closed after pressing: " + buttonText, !addRemoveDialog.isShowing());
	}

	private void enterAddressRange(boolean isSource, String buttonText, AddressRange addressRange) {
		enterAddressRange(isSource, buttonText, addressRange.getMinAddress(),
			addressRange.getMaxAddress());
	}

	private void changeAddressSetsPanel(AddressSetChoice sourceChoice,
			AddressSetChoice destinationChoice, VTWizardPanelAction wizardAction) {

		changeAddressSetChoices(sourceChoice, destinationChoice);

		SystemUtilities.runSwingNow(() -> invoke(wizardAction));
	}

	private void createSelectionInSourceAndDestinationTools() {
		// Create a selection in Source Tool and in Destination Tool.
		VTSubToolManager toolManager = plugin.getToolManager();
		PluginTool sourceTool = (PluginTool) TestUtils.getInstanceField("sourceTool", toolManager);
		assertNotNull(sourceTool);
		PluginTool destinationTool =
			(PluginTool) TestUtils.getInstanceField("destinationTool", toolManager);
		assertNotNull(destinationTool);

		setSelectionInTool(sourceTool, sourceSelection);

		setSelectionInTool(destinationTool, destinationSelection);
	}

	private void checkSummaryPanel(String labelString, String summaryString,
			VTWizardPanelAction wizardAction) {

		// Address Set Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof SummaryPanel);
		SummaryPanel summaryPanel = (SummaryPanel) currentWizardPanel;

		JLabel labelLabel = (JLabel) TestUtils.getInstanceField("labelLabel", summaryPanel);
		assertNotNull(labelLabel);

		JLabel summaryLabel = (JLabel) TestUtils.getInstanceField("summaryLabel", summaryPanel);
		assertNotNull(summaryLabel);

		String labelText = labelLabel.getText();
		String summaryText = summaryLabel.getText();
		assertEquals(labelString, labelText);
		assertEquals(summaryString, summaryText);

		runSwingLater(() -> invoke(wizardAction));
		waitForSwing();
	}

	private int getRowWithFieldValueInColumn(String string, TableModel model, int column) {
		int rowCount = model.getRowCount();
		for (int row = 0; row < rowCount; row++) {
			if (string.equals(model.getValueAt(row, column))) {
				return row;
			}
		}
		return -1;
	}

	private int getNamedColumnIndex(String name, TableModel model) {
		int columnCount = model.getColumnCount();
		for (int column = 0; column < columnCount; column++) {
			if (name.equals(model.getColumnName(column))) {
				return column;
			}
		}
		return -1;
	}

	private void waitForButtonToSelect(JRadioButton button, int maxTimeMS) {
		int totalTime = 0;
		while (totalTime <= maxTimeMS) {
			if (button.isSelected()) {
				return;
			}
			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}
	}

	private void checkWizardButtonEnablement(boolean backEnabled, boolean nextEnabled,
			boolean finishEnabled, boolean cancelEnabled) {
		JComponent component = wizardManager.getComponent();
		JButton backButton = findButtonByText(component, "<< Back");
		JButton nextButton = findButtonByText(component, "Next >>");
		JButton finishButton = findButtonByText(component, "Finish");
		JButton cancelButton = findButtonByText(component, "Cancel");
		assertNotNull(backButton);
		assertNotNull(nextButton);
		assertNotNull(finishButton);
		assertNotNull(cancelButton);
		assertEquals("Back button enablement", backEnabled, backButton.isEnabled());
		assertEquals("Next button enablement", nextEnabled, nextButton.isEnabled());
		assertEquals("Finish button enablement", finishEnabled, finishButton.isEnabled());
		assertEquals("Cancel button enablement", cancelEnabled, cancelButton.isEnabled());
	}

	public void invoke(VTWizardPanelAction wizardAction) {
		switch (wizardAction) {
			case BACK:
				wizardManager.back();
				break;
			case NEXT:
				wizardManager.next();
				break;
			case FINISH:
				wizardManager.finish();
				break;
			case CANCEL:
				wizardManager.close();
				break;
		}
	}

	private void setSelectionInTool(PluginTool subTool, AddressSet sourceSelection) {
		CodeViewerService service = subTool.getService(CodeViewerService.class);
		if (service == null) {
			Assert.fail("Couldn't get listing for tool: " + subTool.getName());
		}
		service.getListingPanel().setSelection(new ProgramSelection(sourceSelection));
	}

	private Address sourceAddress(String addressString) {
		return sourceProgram.getAddressFactory().getAddress(addressString);
	}

	private Address destinationAddress(String addressString) {
		return destinationProgram.getAddressFactory().getAddress(addressString);
	}

	private void createWizardManager() {
		runSwing(() -> {
			vtWizardManager = new VTAddToSessionWizardManager(controller);
			wizardManager = new WizardManager("Version Tracking Wizard", true, vtWizardManager);
		});
	}
}
