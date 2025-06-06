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
package ghidra.app.plugin.core.progmgr;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingAction;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.searchlist.SearchList;
import docking.widgets.searchlist.SearchListModel;
import docking.widgets.tab.*;
import generic.test.TestUtils;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.services.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for the plugin that manages the tab for multiple open programs.
 */

public class MultiTabPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private String[] programNames = { "notepad", "login", "tms" };
	private Program[] programs;
	private ProgramManager pm;
	private GTabPanel<Program> panel;
	private MarkerService markerService;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(MultiTabPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		pm = tool.getService(ProgramManager.class);
		markerService = tool.getService(MarkerService.class);
		env.showTool();

		reconfigureTimerSpeedForTests();
	}

	private void reconfigureTimerSpeedForTests() {
		//
		// Hacky: replace the real timer with our test equivalent so that we may speed
		// things up a bit.
		//
		MultiTabPlugin plugin = env.getPlugin(MultiTabPlugin.class);
		String timerFieldName = "selectHighlightedProgramTimer";
		Timer realTimer = (Timer) getInstanceField(timerFieldName, plugin);
		Timer testTimer = new Timer(10, e -> realTimer.getActionListeners()[0].actionPerformed(e));
		testTimer.setRepeats(false);

		setInstanceField(timerFieldName, plugin, testTimer);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testOpenPrograms() throws Exception {
		openPrograms(programNames);
		assertNotNull(panel);
		assertEquals(programNames.length, panel.getTabCount());
		assertEquals(programs[programs.length - 1], getSelectedTabValue());
	}

	@Test
	public void testAddExisting() throws Exception {
		openPrograms(programNames);
		assertEquals(programNames.length, panel.getTabCount());

		panel.addTab(programs[0]);
		assertEquals(programNames.length, panel.getTabCount());
	}

	@Test
	public void testSelectTab() throws Exception {
		openPrograms(programNames);

		// select second tab
		JPanel tab = panel.getTab(programs[1]);
		Point p = tab.getLocationOnScreen();
		clickMouse(tab, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);
		assertEquals(programs[1], getSelectedTabValue());

		// select first tab
		tab = panel.getTab(programs[0]);
		p = tab.getLocationOnScreen();
		clickMouse(tab, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);
		assertEquals(programs[0], getSelectedTabValue());
	}

	@Test
	public void testCloseTab() throws Exception {
		openPrograms(programNames);

		// select second tab
		JPanel tab = panel.getTab(programs[1]);
		JLabel iconLabel = (JLabel) findComponentByName(tab, "Close");
		assertNotNull(iconLabel);
		Point p = iconLabel.getLocationOnScreen();
		clickMouse(iconLabel, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);

		JDialog dlg = waitForJDialog("Program Changed");
		JButton button = findButtonByText(dlg, "Continue");
		pressButton(button);

		waitForSwing();

		assertEquals(2, panel.getTabCount());
	}

	@Test
	public void testCloseHidden() throws Exception {
		tool.getToolFrame().setSize(new Dimension(500, 500));

		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);
		assertEquals(3, panel.getHiddenTabs().size());

		runSwing(() -> panel.removeTab(programs[3]));
		assertEquals(2, panel.getHiddenTabs().size());
	}

	@Test
	public void testCloseAll() throws Exception {
		openPrograms(programNames);

		for (int i = 0; i < programs.length - 1; i++) {
			JPanel tab = panel.getTab(programs[i]);
			JLabel iconLabel = (JLabel) findComponentByName(tab, "Close");
			Point p = iconLabel.getLocationOnScreen();
			clickMouse(iconLabel, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);

			JDialog dlg = waitForJDialog("Program Changed");
			JButton button = findButtonByText(dlg, "Continue");
			pressButton(button);
		}

		// Last program does not have a tab
		ProgramManagerPlugin programMgr = env.getPlugin(ProgramManagerPlugin.class);
		runSwingLater(() -> programMgr.closeProgram());

		waitForSwing();

		JDialog dlg = waitForJDialog("Program Changed");
		JButton button = findButtonByText(dlg, "Continue");
		pressButton(button);

		waitForSwing();

		assertEquals(0, panel.getTabCount());
	}

	@Test
	public void testShowList() throws Exception {
		setFrameSize(650, 500);

		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);

		assertEquals(programNames.length, panel.getTabCount());
		assertEquals(3, panel.getVisibleTabs().size());
		assertEquals(2, panel.getHiddenTabs().size());

		TabListPopup<?> tabListPopup = showList();

		@SuppressWarnings("unchecked")
		SearchList<Program> list = findComponent(tabListPopup, SearchList.class);
		assertNotNull(list);
		SearchListModel<Program> model = list.getModel();
		Program[] hiddenPrograms = new Program[] { programs[2], programs[3] };// 4 tabs fit before 5th program was open
		for (int i = 0; i < hiddenPrograms.length; i++) {
			assertEquals(hiddenPrograms[i], model.getElementAt(i).value());
		}

		Program[] shownPrograms = new Program[] { programs[0], programs[1], programs[4] };
		for (int i = 0; i < shownPrograms.length; i++) {
			assertEquals(shownPrograms[i], model.getElementAt(i + 2).value());
		}
	}

	@Test
	public void testSelectFromList() throws Exception {
		setFrameSize(500, 500);

		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);

		TabListPopup<?> tabListPopup = showList();

		@SuppressWarnings("unchecked")
		SearchList<Program> list = findComponent(tabListPopup, SearchList.class);
		list.setSelectedItem(programs[1]);
		triggerText(list.getFilterField(), "\n");
		assertEquals(programs[1], getSelectedTabValue());
	}

	@Test
	public void testCloseAllWithListShowing() throws Exception {
		setFrameSize(400, 500);

		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);

		TabListPopup<?> tabListPopup = showList();
		Window window = windowForComponent(tabListPopup);
		assertTrue(window.isShowing());

		// remove notepad
		runSwing(() -> panel.removeTab(programs[0]));

		assertTrue(!window.isShowing());
	}

	@Test
	public void testResize() throws Exception {
		setFrameSize(500, 500);
		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);

		HiddenValuesButton control = findComponent(tool.getToolFrame(), HiddenValuesButton.class);
		assertNotNull(control);

		assertEquals(programNames.length, panel.getTabCount());
		assertEquals(2, panel.getVisibleTabs().size());
		assertEquals(3, panel.getHiddenTabs().size());

		setFrameSize(925, 500);

		control = findComponent(tool.getToolFrame(), HiddenValuesButton.class);

		assertNull(control);
		assertEquals(5, panel.getVisibleTabs().size());
		assertEquals(0, panel.getHiddenTabs().size());
	}

	@Test
	public void testTabUpdatesOnProgramChange() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test", "0x0", 100);
		Program p = doOpenProgram(builder.getProgram(), true);
		p.setTemporary(false); // we need to be notified of changes 
		// select notepad
		selectTab(p);
		int transactionID = p.startTransaction("test");
		try {
			SymbolTable symTable = p.getSymbolTable();
			symTable.createLabel(builder.addr("0x10"), "fred", SourceType.USER_DEFINED);
		}
		finally {
			p.endTransaction(transactionID, true);
		}
		p.flushEvents();
		runSwing(() -> panel.refreshTab(p));

		JPanel tab = panel.getTab(p);
		JLabel label = (JLabel) findComponentByName(tab, "Tab Label");
		assertTrue(label.getText().startsWith("*"));
	}

	@Test
	public void testSetSelectedObject() throws Exception {
		setFrameSize(400, 500);
		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);
		assertHidden(programs[1]);

		runSwing(() -> panel.selectTab(programs[1]));
		assertEquals(programs[1], getSelectedTabValue());
		assertShowing(programs[1]);
	}

	@Test
	public void testGoToLastProgramAction() throws Exception {

		openPrograms_HideLastOpened();

		Program startProgram = getSelectedTabValue();

		MultiTabPlugin plugin = env.getPlugin(MultiTabPlugin.class);
		DockingAction action =
			(DockingAction) TestUtils.getInstanceField("goToLastActiveProgramAction", plugin);
		assertTrue(!action.isEnabled());// disabled before we've changed tabs

		// select second tab
		JPanel tab = panel.getTab(programs[1]);
		Point p = tab.getLocationOnScreen();
		clickMouse(tab, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);
		assertEquals(programs[1], getSelectedTabValue());
		assertTrue(!startProgram.equals(getSelectedTabValue()));

		assertTrue(action.isEnabled());

		performAction(action, true);
		assertEquals(startProgram, getSelectedTabValue());
	}

	@Test
	public void testStateOnSwitch() throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		setFrameSize(400, 500);

		Program p1 = openDummyProgram("notepad", true);
		Program p2 = openDummyProgram("login", true);

		ProgramManager programManager = tool.getService(ProgramManager.class);
		programManager.setCurrentProgram(p1);

		MarkerSet set = createMarkers(p1);
		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);
		FieldPanel fp = cb.getFieldPanel();
		Address address = cb.getListingPanel().getAddressIndexMap().getAddress(BigInteger.ZERO);
		runSwing(() -> {
			set.add(address);
			fp.setCursorPosition(BigInteger.valueOf(4), 0, 0, 0);
		});

		assertEquals(BigInteger.valueOf(4), fp.getCursorLocation().getIndex());

		programManager.setCurrentProgram(p2);
		assertEquals(BigInteger.ZERO, fp.getCursorLocation().getIndex());

		programManager.setCurrentProgram(p1);
		assertEquals(BigInteger.valueOf(4), fp.getCursorLocation().getIndex());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testTabUpdate() throws Exception {
		Program p = openDummyProgram("login", true);

		// select second tab (the "login" program)
		panel = findComponent(tool.getToolFrame(), GTabPanel.class);

		// don't let focus issues hide the popup list
		panel.setIgnoreFocus(true);

		selectTab(p);
		assertEquals(p, getSelectedTabValue());

		addComment(p);

		String oldName = p.getName();
		String newName = "myNewLogin";
		renameProgramFile(p, newName);
		ArrayList<DomainObjectChangeRecord> changeRecs = new ArrayList<>();
		changeRecs.add(
			new DomainObjectChangeRecord(DomainObjectEvent.RENAMED, oldName, p.getName()));
		DomainObjectChangedEvent ev = new DomainObjectChangedEvent(p, changeRecs);
		runSwing(() -> env.getPlugin(MultiTabPlugin.class).domainObjectChanged(ev));

		// Check the name on the tab and in the tooltip.
		JPanel tabPanel = getTabPanel(p);
		JLabel label = (JLabel) findComponentByName(tabPanel, "Tab Label");
		assertEquals("*" + newName + " [Read-Only]", label.getText());
		assertTrue(label.getToolTipText().endsWith("/" + newName + " [Read-Only]*"));
	}

	@Test
	public void testKeyboardTabNavigation() throws Exception {
		// 
		// Test forward and backward from middle, with no hidden programs
		// 

		//@formatter:off
		programNames = new String[] { 
				"notepad", "login", "tms",       // visible 
				"taskman", "TestGhidraSearches"  // hidden
		};
		//@formatter:on
		openPrograms(programNames);

		// the newly selected program should be the one after 'login'
		selectTab(programs[1]);
		performNextAction();
		assertProgramSelected(programs[2]);

		// the newly selected program should be back to 'login'
		performPreviousAction();
		assertProgramSelected(programs[1]);

		// 
		// test forward and backward from each end, with hidden programs
		//

		// by trial-and-error, we know that 'tms' is the last visible program tab 
		// after resizing
		setFrameSize(550, 500);
		assertShowing(programs[2]);
		assertHidden(programs[3]);

		// select the last visible tab
		selectTab(programs[2]);
		performNextAction();

		// make sure the panel is showing
		Window listWindow = getListWindow();
		assertTrue(listWindow.isShowing());
		listWindow.setVisible(false);

		// select the first visible tab and go backwards to trigger the list
		selectTab(programs[0]);
		performPreviousAction();
		listWindow = getListWindow();
		assertTrue(listWindow.isShowing());
	}

	@Test
	public void testKeyboardNavigationWithListShowing_SCR_9490() throws Exception {
		//
		// Test that the user can keep pressing the next/previous keys with the list
		// open.
		//

		//@formatter:off
		programNames = new String[] { 
				"notepad", "login", "tms",       // visible 
				"taskman", "TestGhidraSearches"  // hidden
		};
		//@formatter:on
		openPrograms_HideLastOpened();

		// by trial-and-error, we know that 'tms' is the last visible program tab 
		// after resizing
		setFrameSize(600, 500);
		assertShowing(programs[2]);
		assertHidden(programs[3]);

		// select 'tms', which is the last tab before the list is shown
		selectTab(programs[2]);
		performNextAction();
		Window window = getListWindow();
		assertTrue(window.isShowing());

		// the newly selected program should the first program, as the selection 
		// should have left the window and wrapped around 'notepad'
		performNextAction();
		assertProgramSelected(programs[0]);
		assertFalse(window.isShowing());

		//
		// Now try the other direction, which should wrap back around the other direction,
		// showing the list, with another action to keep on moving.
		//		
		selectTab(programs[0]);// start off at the first tab	
		performPreviousAction();
		Window listWindow = getListWindow();
		assertTrue(listWindow.isShowing());

		performPreviousAction();
		assertProgramSelected(programs[2]);// 'tms'--last visible program
		assertFalse(listWindow.isShowing());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertProgramSelected(Program p) {
		Program selectedProgram = getSelectedTabValue();
		assertEquals(selectedProgram, p);
	}

	private void assertShowing(Program p) throws Exception {
		waitForConditionWithoutFailing(() -> {
			boolean isHidden = runSwing(() -> panel.getHiddenTabs().contains(p));
			return !isHidden;
		});

		boolean isHidden = runSwing(() -> panel.getHiddenTabs().contains(p));
		if (isHidden) {
			capture(tool.getToolFrame(), "multi.tabs.program2.should.be.showing");
		}

		assertFalse(runSwing(() -> panel.getHiddenTabs().contains(p)));
	}

	private void assertHidden(Program p) {
		assertTrue(runSwing(() -> panel.getHiddenTabs().contains(p)));
	}

	private MarkerSet createMarkers(final Program p) {
		final AtomicReference<MarkerSet> ref = new AtomicReference<>();
		runSwing(() -> ref.set(markerService.createPointMarker("Test", "Test", p, 40, false, false,
			true, Palette.BLUE, null)));
		return ref.get();
	}

	private Window getListWindow() {
		TabListPopup<?> tabList =
			(TabListPopup<?>) waitForWindowByTitleContaining("Popup Window Showing");

		return tabList;
	}

	private void performPreviousAction() throws Exception {
		MultiTabPlugin plugin = env.getPlugin(MultiTabPlugin.class);
		DockingAction goToPreviousProgramAction =
			(DockingAction) TestUtils.getInstanceField("goToPreviousProgramAction", plugin);
		performAction(goToPreviousProgramAction, true);
		Thread.sleep(100);// wait for the selection timer to execute 
		waitForSwing();
	}

	private void performNextAction() throws Exception {
		MultiTabPlugin plugin = env.getPlugin(MultiTabPlugin.class);
		DockingAction goToNextProgramAction =
			(DockingAction) TestUtils.getInstanceField("goToNextProgramAction", plugin);
		assertTrue(goToNextProgramAction.isEnabled());

		performAction(goToNextProgramAction, true);
		Thread.sleep(100);// wait for the selection timer to execute 
		waitForSwing();
	}

	private void selectTab(Program p) {
		JPanel tab = runSwing(() -> panel.getTab(p));
		Point point = runSwing(() -> tab.getLocationOnScreen());
		clickMouse(tab, MouseEvent.BUTTON1, point.x + 1, point.y + 1, 1, 0);
		assertEquals(p, getSelectedTabValue());
	}

	private Program getSelectedTabValue() {
		return runSwing(() -> panel.getSelectedTabValue());
	}

	private JPanel getTabPanel(Program p) {

		final AtomicReference<JPanel> ref = new AtomicReference<>();
		runSwing(() -> ref.set(panel.getTab(p)));
		return ref.get();
	}

	private void renameProgramFile(final Program p, final String name) {
		Runnable r = () -> {
			try {
				p.getDomainFile().setName(name);
			}
			catch (Exception e) {
				e.printStackTrace();
				Assert.fail(e.getMessage());
			}
		};
		runSwing(r, true);
		waitForSwing();
	}

	private void addComment(Program p) {
		int transactionID = p.startTransaction("test");
		try {
			p.getListing()
					.setComment(p.getAddressFactory().getAddress("01000000"),
						CommentType.REPEATABLE, "This is a simple comment change.");
		}
		finally {
			p.endTransaction(transactionID, true);
		}
		p.flushEvents();
		waitForSwing();
	}

	private void openPrograms_HideLastOpened() throws Exception {
		boolean makeCurrent = true;
		programs = new Program[programNames.length];
		for (int i = 0; i < programNames.length; i++) {
			programs[i] = openDummyProgram(programNames[i], makeCurrent);
			makeCurrent = false;
		}
	}

	private Program openDummyProgram(String name, boolean makeCurrent) throws Exception {

		ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._TOY);
		builder.createMemory(".text", "0x01000000", 0x100);
		Program program = builder.getProgram();
		program.setTemporary(false); // some tests want to be notified of changes
		return doOpenProgram(program, makeCurrent);
	}

	@SuppressWarnings("unchecked")
	private Program doOpenProgram(Program p, boolean makeCurrent) {
		runSwing(() -> {
			int programState =
				makeCurrent ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE;
			pm.openProgram(p, programState);
			panel = findComponent(tool.getToolFrame(), GTabPanel.class);

			// don't let focus issues hide the popup list
			panel.setIgnoreFocus(true);
			panel.setShowTabsAlways(true);
		});
		waitForSwing();
		return p;
	}

	private void openPrograms(String[] names) throws Exception {
		programs = new Program[names.length];
		for (int i = 0; i < names.length; i++) {
			programs[i] = openDummyProgram(names[i], true);
		}

	}

	private void setFrameSize(int width, int height) throws Exception {
		final Dimension d = new Dimension(width, height);
		runSwing(() -> {
			JFrame f = tool.getToolFrame();
			f.setSize(d);
			f.invalidate();
			f.validate();
			f.repaint();
		});
		waitForSwing();
	}

	private TabListPopup<?> showList() {
		HiddenValuesButton control = findComponent(panel, HiddenValuesButton.class);
		Point p = control.getLocationOnScreen();
		clickMouse(control, MouseEvent.BUTTON1, p.x + 3, p.y + 2, 1, 0);
		waitForSwing();
		TabListPopup<?> tabList =
			(TabListPopup<?>) waitForWindowByTitleContaining("Popup Window Showing");
		assertNotNull(tabList);
		return tabList;
	}

}
