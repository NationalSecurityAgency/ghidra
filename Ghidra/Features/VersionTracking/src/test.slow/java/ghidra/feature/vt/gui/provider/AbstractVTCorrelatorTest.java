/* ###
 * IP: GHIDRA
 * NOTE: This class provides setup and tear-down functions as well as functions
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

import static ghidra.feature.vt.db.VTTestUtils.createProgramCorrelator;
import static ghidra.feature.vt.db.VTTestUtils.createRandomMatch;
import static org.junit.Assert.*;

import java.awt.Component;
import java.util.*;
import java.util.concurrent.TimeUnit;

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.After;
import org.junit.Before;

import docking.options.editor.OptionsEditorPanel;
import docking.wizard.WizardManager;
import docking.wizard.WizardPanel;
import generic.lsh.LSHMemoryModel;
import generic.test.TestUtils;
import ghidra.feature.vt.api.correlator.program.VTAbstractReferenceProgramCorrelatorFactory;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.task.AcceptMatchTask;
import ghidra.feature.vt.gui.task.ApplyMatchTask;
import ghidra.feature.vt.gui.wizard.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * An abstract class for Correlator Tests.
 */
public abstract class AbstractVTCorrelatorTest extends AbstractGhidraHeadedIntegrationTest {

	private String sourceProgLoc;
	private String destProgLoc;

	protected VTTestEnv env;
	protected VTSessionDB session;
	protected Program srcProg;
	protected Program destProg;
	protected VTController controller;
	protected VTPlugin plugin;
	protected VTAddToSessionWizardManager vtWizardManager;
	protected WizardManager wizardManager;

	public AbstractVTCorrelatorTest(String sourceProgLoc, String destProgLoc) {
		super();
		this.sourceProgLoc = sourceProgLoc;
		this.destProgLoc = destProgLoc;
	}

	@Before
	public void setUp() throws Exception {

		env = new VTTestEnv();
		PluginTool tool = env.showTool();

		plugin = env.getVersionTrackingPlugin();
		controller = env.getVTController();

		session = env.createSession(sourceProgLoc, destProgLoc);
		assertNotNull(session);

		srcProg = env.getSourceProgram();
		destProg = env.getDestinationProgram();

		JFrame toolFrame = tool.getToolFrame();
		toolFrame.setSize(800, 800);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private void setupWizardBeforeCorrelatorOptions(String correlatorName) {

		runSwing(() -> {
			vtWizardManager = new VTAddToSessionWizardManager(controller);
			wizardManager = new WizardManager("Version Tracking Wizard", true, vtWizardManager);
			wizardManager.showWizard(controller.getParentComponent());
		}, false);

		waitForSwing();
		waitForDialogComponent(WizardManager.class);
		assertNotNull(wizardManager);

		checkWizardButtonEnablement(false, false, false, true);
		chooseFromCorrelationPanel(correlatorName, wizardManager::next);

		checkWizardButtonEnablement(true, true, true, true);
	}

	private void finishWizardAfterCorrelatorOptions(String correlatorName) {
		checkAddressSetOptionsPanel(false, false);
		checkWizardButtonEnablement(true, true, true, true);
		changeAddressSetOptionsPanel(false, false, wizardManager::next);

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);

		// Check the summary panel.
		checkWizardButtonEnablement(true, false, true, true);
		String labelString = "<html>" + "Operation:<br>" + "Session Name:<br>" +
			"Source Program:<br>" + "Destination Program:<br>" + "Program Correlator:<br>" +
			"Exclude Accepted Matches:<br>" + "Source Address Set:<br>" +
			"Destination Address Set:<br>" + "</html>";
		String summaryString = "<html>" + "Add to Version Tracking Session<br>" +
			session.getName() + "<br>" + srcProg.getName() + "<br>" + destProg.getName() + "<br>" +
			correlatorName + "<br>" + "No<br>" + "Entire Source Program<br>" +
			"Entire Destination Program<br>" + "</html>";
		checkSummaryPanel(HTMLUtilities.toHTML(labelString), HTMLUtilities.toHTML(summaryString),
			wizardManager::finish);
	}

	public void runTestCorrelator(String correlatorName) {
		runTestCorrelatorWithDefaultOptions(correlatorName);
	}

	/**
	 * Automatically navigate the VT correlator GUI in order to run the indicated correlator
	 * without changing any of its options.
	 * @param correlatorName the name of the correlator being run by the GUI.
	 */
	public void runTestCorrelatorWithDefaultOptions(String correlatorName) {

		long start = System.nanoTime();
		setupWizardBeforeCorrelatorOptions(correlatorName);

		useDefaultCorrelatorOptions(correlatorName, wizardManager::next);

		finishWizardAfterCorrelatorOptions(correlatorName);

		long end = System.nanoTime();
		long total = TimeUnit.MILLISECONDS.convert(end - start, TimeUnit.NANOSECONDS);
		Msg.debug(this, "Ran correlator '" + correlatorName + "' in '" + total + "' ms");
	}

	/**
	 * Run the version tracking wizard for the indicated reference program correlator to create a
	 * new session. Use the indicated values for the options.
	 * @param correlatorName the reference program correlator (function, data, or combined).
	 * @param confidence the confidence threshold from 0.0 to 1.0
	 * @param memoryModel indicates the memory model's size
	 * @param score minimum similarity threshold (defaults to 0.5)
	 * @param refineResults true to remove low scoring results from created matches
	 */
	public void runTestReferenceCorrelatorWithOptions(String correlatorName,
			final double confidence, final LSHMemoryModel memoryModel, final double score,
			boolean refineResults) {

		setupWizardBeforeCorrelatorOptions(correlatorName);

		changeReferenceCorrelatorOptions(correlatorName, confidence, memoryModel, score,
			refineResults, wizardManager::next);

		finishWizardAfterCorrelatorOptions(correlatorName);
	}

	public boolean verifyExternalAddressesName(Program prog, Address extAddr, String name) {
		SymbolIterator symbols = prog.getSymbolTable().getSymbols(name);
		while (symbols.hasNext()) {
			Symbol nextSym = symbols.next();
			if (nextSym.getAddress().equals(extAddr)) {
				return true;
			}
		}
		return false;
	}

	public VTAssociationPair toPair(VTMatch vtMatch) {
		Address src = vtMatch.getSourceAddress();
		Address dst = vtMatch.getDestinationAddress();
		return new VTAssociationPair(src, dst, vtMatch.getAssociation().getType());
	}

	public Set<VTAssociationPair> getMatchAddressPairs(VTMatchSet matchSet) {

		Set<VTAssociationPair> pairs = new HashSet<>();

		Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch vtMatch : matches) {
			pairs.add(toPair(vtMatch));
		}

		return pairs;
	}

	protected VTMatchSet getVTMatchSet(String correlatorName) {
		List<VTMatchSet> matchSets = session.getMatchSets();
		Iterator<VTMatchSet> iterator = matchSets.iterator();
		VTMatchSet returnMatchSet = null;
		while (iterator.hasNext()) {
			VTMatchSet vtMatchSet = iterator.next();
			if (vtMatchSet.getProgramCorrelatorInfo().getName().equals(correlatorName)) {
				returnMatchSet = vtMatchSet;
			}
		}
		return returnMatchSet;
	}

	protected boolean isMatch(Address srcAddr, Address destAddr, VTMatchSet vtMatchSet) {

		if (vtMatchSet.getMatches(srcAddr, destAddr).size() > 0) {
			return true;
		}
		return false;
	}

	protected Address addr(Program program, String address) {
		AddressFactory addrFactory = program.getAddressFactory();
		return addrFactory.getAddress(address);
	}

	protected Address externalAddrFor(Program program, String name) {
		// Assume Library.UNKNOWN "<EXTERNAL>" namespace
		ExternalLocation extLoc =
			program.getExternalManager().getUniqueExternalLocation(Library.UNKNOWN, name);
		assertTrue("External function not found: " + name, extLoc != null && extLoc.isFunction());
		return extLoc.getExternalSpaceAddress();
	}

	protected VTMatchSet createMatchSet(VTSessionDB db, List<VTAssociationPair> list)
			throws Exception {
		int testTransactionID = 0;
		try {
			testTransactionID = db.startTransaction("Test Match Set Setup");
			VTMatchSet matchSet = db.createMatchSet(
				createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));
			for (VTAssociationPair associationPair : list) {
				VTMatchInfo info = createRandomMatch(associationPair.getSource(),
					associationPair.getDestination(), db);
				info.setAssociationType(associationPair.getType());
				matchSet.addMatch(info);
			}
			return matchSet;
		}
		finally {
			db.endTransaction(testTransactionID, true);
		}
	}

	protected VTAssociationPair associate(Address source, Address dest, VTAssociationType type) {
		return new VTAssociationPair(source, dest, type);
	}

	protected VTAssociationPair associate(Address source, Address dest) {
		return new VTAssociationPair(source, dest, VTAssociationType.FUNCTION);
	}

	/**
	 * Return the VTMatch from matchSet that corresponds to sourceAddress and destinationAddress.
	 * If more than one match is found, this function will fail.
	 *
	 * @param matchSet The {@code VTMatchSet}.
	 * @param sourceAddress The {@code Address} in the source program.
	 * @param destinationAddress The {@code Address} in the destination program.
	 * @return
	 */
	protected VTMatch getMatch(VTMatchSet matchSet, Address sourceAddress,
			Address destinationAddress) {
		Collection<VTMatch> desiredMatches = matchSet.getMatches(sourceAddress, destinationAddress);
		assertEquals(1, desiredMatches.size());
		VTMatch matchToApply = desiredMatches.iterator().next();
		return matchToApply;
	}

	protected boolean hasHigherScore(VTMatch matchA, VTMatch matchB) {
		double simA = matchA.getSimilarityScore().getScore();
		double simB = matchB.getSimilarityScore().getScore();
		double confA = matchA.getConfidenceScore().getScore();
		double confB = matchB.getConfidenceScore().getScore();

		if (simA < simB) {
			return false;
		}

		if (simA > simB) {
			return (confA >= confB);
		}

		// else simA == simB
		return (confA > confB);
	}

	protected void applyMatch(VTMatch match) throws Exception {
		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);
	}

	protected void acceptMatch(VTMatch match) throws Exception {
		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		AcceptMatchTask task = new AcceptMatchTask(controller, matches);
		runTask(task);
	}

	protected void assertMatchPairs(Set<VTAssociationPair> expected,
			Set<VTAssociationPair> actual) {
		assertMissingMatchPairs(expected, actual);
		assertExtraMatchPairs(expected, actual);
	}

	private void assertMissingMatchPairs(Set<VTAssociationPair> expected,
			Set<VTAssociationPair> actual) {

		String expectedMissing = getMissingMatchPairs(expected, actual);
		assertTrue(expectedMissing, actual.containsAll(expected));
	}

	private void assertExtraMatchPairs(Set<VTAssociationPair> expected,
			Set<VTAssociationPair> actual) {
		assertTrue(getExtraMatchPairs(expected, actual), expected.containsAll(actual));
	}

	protected String getMissingMatchPairs(Set<VTAssociationPair> expected,
			Set<VTAssociationPair> actual) {
		return getMatchPairsOnlyInFirst(expected, actual, "missing");
	}

	protected String getExtraMatchPairs(Set<VTAssociationPair> expected,
			Set<VTAssociationPair> actual) {
		return getMatchPairsOnlyInFirst(actual, expected, "extra");
	}

	private String getMatchPairsOnlyInFirst(Set<VTAssociationPair> firstMatchPairs,
			Set<VTAssociationPair> secondMatchPairs, String type) {
		StringBuilder buffy = new StringBuilder();
		for (VTAssociationPair expectedMatch : firstMatchPairs) {
			if (!secondMatchPairs.contains(expectedMatch)) {
				if (buffy.length() > 0) {
					buffy.append(", ");
				}
				buffy.append("[src: " + expectedMatch.getSource() + " dst: " +
					expectedMatch.getDestination() + "]");
			}
		}
		if (buffy.length() > 0) {
			return "The following matches were " + type + ": " + buffy.toString();
		}
		return "No " + type + " matches!";
	}

	/**
	 * Run Dummy Task Monitor, flush events and wait for Swing.
	 * @param task
	 * @throws Exception 
	 */
	protected void runTask(Task task) throws Exception {

		task.run(TaskMonitorAdapter.DUMMY_MONITOR);
		destProg.flushEvents();
		waitForSwing();
		waitForTasks();
	}

	protected void checkWizardButtonEnablement(boolean backEnabled, boolean nextEnabled,
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

	protected void chooseFromCorrelationPanel(final String correlatorName, Runnable wizardAction) {

		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof CorrelatorPanel);
		CorrelatorPanel correlatorPanel = (CorrelatorPanel) currentWizardPanel;
		runSwing(() -> {
			GhidraTable table = (GhidraTable) TestUtils.getInstanceField("table", correlatorPanel);
			TableModel model = table.getModel();
			int column = getNamedColumnIndex("Name", model);
			assertTrue(column >= 0);
			int row = getRowWithFieldValueInColumn(correlatorName, model, column);
			assertTrue(row >= 0);
			model.setValueAt(Boolean.TRUE, row, 0);
			wizardAction.run();
		});
	}

	protected void changeCorrelatorOptionsPanel(Object correlatorOptionsObject,
			Runnable wizardAction) {

		// Options Panel
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof OptionsPanel);

		runSwing(wizardAction);
	}

	/**
	 * Uses default values for the options used by the named correlator in the version tracking wizard.
	 * @param correlatorName the name of the program correlator.
	 * @param wizardAction wizard action to take on the correlator panel.
	 */
	protected void useDefaultCorrelatorOptions(final String correlatorName, Runnable wizardAction) {

		OptionsEditorPanel correlatorOptionsPanel = getCorrelatorOptionsPanel(correlatorName);
		assertNotNull(correlatorOptionsPanel);
		runSwing(wizardAction);
	}

	/**
	 * Updates the values for the options used by the named correlator in the version tracking wizard.
	 * @param correlatorName the reference program correlator (function, data, or combined).
	 * @param confidence the confidence threshold from >=0.0 (defaults to 1.0)
	 * @param memoryModel indicates the memory model's size
	 * @param score minimum similarity threshold 0.0 to 1.0 (defaults to 0.5)
	 * @param refineResults true to remove low scoring results from created matches
	 * @param wizardAction wizard action to take on the correlator panel.
	 */
	protected void changeReferenceCorrelatorOptions(final String correlatorName,
			final double confidence, final LSHMemoryModel memoryModel, final double score,
			boolean refineResults, Runnable wizardAction) {

		runSwing(() -> {
			OptionsEditorPanel correlatorOptionsPanel = getCorrelatorOptionsPanel(correlatorName);

			@SuppressWarnings("unchecked")
			List<EditorState> editorInfoList =
				(List<EditorState>) TestUtils.getInstanceField("editorInfoList",
					correlatorOptionsPanel);
			for (EditorState editorState : editorInfoList) {
				String optionName = editorState.getTitle();
				Component editorComponent = editorState.getEditorComponent();

				if (optionName.equals(
					VTAbstractReferenceProgramCorrelatorFactory.CONFIDENCE_THRESHOLD)) {
					PropertyText fieldText = (PropertyText) editorComponent;
					fieldText.setText(String.format("%f", confidence));
					fieldText.repaint();
				}
				else if (optionName.equals(
					VTAbstractReferenceProgramCorrelatorFactory.MEMORY_MODEL)) {
					PropertySelector selector = (PropertySelector) editorComponent;
					selector.setSelectedItem(memoryModel);
					selector.repaint();
				}
				else if (optionName.equals(
					VTAbstractReferenceProgramCorrelatorFactory.SIMILARITY_THRESHOLD)) {
					PropertyText fieldText = (PropertyText) editorComponent;
					fieldText.setText(String.format("%f", score));
					fieldText.repaint();
				}
				else if (optionName.equals(
					VTAbstractReferenceProgramCorrelatorFactory.REFINE_RESULTS)) {
					PropertyBoolean checkBox = (PropertyBoolean) editorComponent;
					checkBox.setSelected(refineResults);
					checkBox.repaint();
				}
			}
		});

		runSwing(wizardAction);
	}

	private OptionsEditorPanel getCorrelatorOptionsPanel(String correlatorName) {
		String desiredTitle = correlatorName + " Options";
		WizardPanel currentWizardPanel = wizardManager.getCurrentWizardPanel();
		assertNotNull(currentWizardPanel);
		assertTrue(currentWizardPanel instanceof OptionsPanel);
		OptionsPanel optionsPanel = (OptionsPanel) currentWizardPanel;
		Object instanceField = TestUtils.getInstanceField("optionsEditorPanelList", optionsPanel);
		@SuppressWarnings("unchecked")
		List<OptionsEditorPanel> optionsEditorPanelList = (List<OptionsEditorPanel>) instanceField;
		OptionsEditorPanel correlatorOptionsPanel = null;
		for (OptionsEditorPanel optionsEditorPanel : optionsEditorPanelList) {
			String title = (String) TestUtils.getInstanceField("title", optionsEditorPanel);
			if (desiredTitle.equals(title)) {
				correlatorOptionsPanel = optionsEditorPanel;
				break;
			}
		}
		assertNotNull(correlatorOptionsPanel);
		return correlatorOptionsPanel;
	}

	/**
	 * Verify the Address Set Options panel.
	 * @param excludeAccepted
	 * @param limitAddressSets
	 */
	protected void checkAddressSetOptionsPanel(boolean excludeAccepted, boolean limitAddressSets) {

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

	protected void changeAddressSetOptionsPanel(boolean excludeAccepted, boolean limitAddressSets,
			Runnable wizardAction) {

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

		runSwing(() -> wizardAction.run());
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

	protected void checkSummaryPanel(final String labelString, final String summaryString,
			Runnable wizardAction) {

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
		assertEquals(labelString, labelText);

		runSwing(wizardAction);
	}

}
