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
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.Timer;

import org.junit.*;

import docking.action.DockingAction;
import docking.widgets.fieldpanel.FieldPanel;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.services.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
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
	private MultiTabPanel panel;
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
		assertEquals(programs[programs.length - 1], panel.getSelectedProgram());
	}

	@Test
	public void testAddExisting() throws Exception {
		openPrograms(programNames);
		assertEquals(programNames.length, panel.getTabCount());

		panel.addProgram(programs[0]);
		assertEquals(programNames.length, panel.getTabCount());
	}

	@Test
	public void testSelectTab() throws Exception {
		openPrograms(programNames);

		// select second tab
		JPanel tab = panel.getTab(programs[1]);
		Point p = tab.getLocationOnScreen();
		clickMouse(tab, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);
		assertEquals(programs[1], panel.getSelectedProgram());

		// select first tab
		tab = panel.getTab(programs[0]);
		p = tab.getLocationOnScreen();
		clickMouse(tab, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);
		assertEquals(programs[0], panel.getSelectedProgram());
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
		assertEquals(2, panel.getTabCount());
	}

	@Test
	public void testCloseHidden() throws Exception {
		tool.getToolFrame().setSize(new Dimension(500, 500));

		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);
		assertEquals(3, panel.getHiddenCount());

		runSwing(() -> panel.removeProgram(programs[3]));
		assertEquals(2, panel.getHiddenCount());
	}

	@Test
	public void testCloseAll() throws Exception {
		openPrograms(programNames);

		for (int i = 0; i < programs.length - 1; i++) {
			JPanel tab = panel.getTab(programs[i]);
			JLabel iconLabel = (JLabel) findComponentByName(tab, "Close");
			Point p = iconLabel.getLocationOnScreen();
			clickMouse(iconLabel, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);
		}

		runSwing(() -> panel.removeProgram(programs[programs.length - 1]));

		assertEquals(0, panel.getTabCount());
	}

	@Test
	public void testShowList() throws Exception {
		setFrameSize(600, 500);

		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);

		assertEquals(programNames.length, panel.getTabCount());
		assertEquals(3, panel.getVisibleTabCount());
		assertEquals(2, panel.getHiddenCount());

		ProgramListPanel listPanel = showList();

		JList<?> list = findComponent(listPanel, JList.class);
		assertNotNull(list);

		ListModel<?> model = list.getModel();
		Program[] hiddenPrograms = new Program[] { programs[2], programs[3] };// 4 tabs fit before 5th program was open
		for (int i = 0; i < hiddenPrograms.length; i++) {
			assertEquals(hiddenPrograms[i], model.getElementAt(i));
		}

		Program[] shownPrograms = new Program[] { programs[0], programs[1], programs[4] };
		for (int i = 0; i < shownPrograms.length; i++) {
			assertEquals(shownPrograms[i], model.getElementAt(i + 2));
		}
	}

	@Test
	public void testSelectFromList() throws Exception {
		setFrameSize(500, 500);

		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);

		ProgramListPanel listPanel = showList();

		JList<?> list = findComponent(listPanel, JList.class);

		// the first item is expected to be 'login', since the current program is
		// 'TestGhidraSearches' and that only fits with 'notepad', the rest our put into the 
		// list in order.
		list.setSelectedIndex(0);
		waitForSwing();

		triggerText(listPanel.getFilterField(), "\n");
		assertEquals(programs[1], panel.getSelectedProgram());
	}

	@Test
	public void testCloseAllWithListShowing() throws Exception {
		setFrameSize(400, 500);

		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);

		ProgramListPanel listPanel = showList();
		Window window = windowForComponent(listPanel);
		assertTrue(window.isShowing());

		// remove notepad
		runSwing(() -> panel.removeProgram(programs[0]));

		assertTrue(!window.isShowing());
	}

	@Test
	public void testResize() throws Exception {
		setFrameSize(500, 500);
		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);
		JLabel listLabel = (JLabel) findComponentByName(panel, "showList");
		assertNotNull(listLabel);
		assertEquals(programNames.length, panel.getTabCount());
		assertEquals(2, panel.getVisibleTabCount());
		assertEquals(3, panel.getHiddenCount());

		setFrameSize(925, 500);

		listLabel = (JLabel) findComponentByName(panel, "showList");

		if (listLabel != null) {
			printResizeDebug();
		}

		assertNull(listLabel);
		assertEquals(5, panel.getVisibleTabCount());
		assertEquals(0, panel.getHiddenCount());
	}

	@Test
	public void testTabUpdatesOnProgramChange() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test", "0x0", 100);
		Program p = doOpenProgram(builder.getProgram(), true);
		p.setTemporary(false); // we need to be notified of changes 

		// select notepad
		panel.setSelectedProgram(p);
		int transactionID = p.startTransaction("test");
		try {
			SymbolTable symTable = p.getSymbolTable();
			symTable.createLabel(builder.addr("0x10"), "fred", SourceType.USER_DEFINED);
		}
		finally {
			p.endTransaction(transactionID, true);
		}
		p.flushEvents();
		runSwing(() -> panel.refresh(p));

		JPanel tab = panel.getTab(p);
		JLabel label = (JLabel) findComponentByName(tab, "objectName");
		assertTrue(label.getText().startsWith("*"));
	}

	@Test
	public void testSetSelectedObject() throws Exception {
		setFrameSize(400, 500);
		programNames = new String[] { "notepad", "login", "tms", "taskman", "TestGhidraSearches" };
		openPrograms(programNames);
		assertHidden(programs[1]);

		runSwing(() -> panel.setSelectedProgram(programs[1]));
		assertEquals(programs[1], panel.getSelectedProgram());
		assertShowing(programs[1]);
	}

	@Test
	public void testGoToLastProgramAction() throws Exception {

		openPrograms_HideLastOpened();

		Program startProgram = panel.getSelectedProgram();

		MultiTabPlugin plugin = env.getPlugin(MultiTabPlugin.class);
		DockingAction action =
			(DockingAction) TestUtils.getInstanceField("goToLastActiveProgramAction", plugin);
		assertTrue(!action.isEnabled());// disabled before we've changed tabs

		// select second tab
		JPanel tab = panel.getTab(programs[1]);
		Point p = tab.getLocationOnScreen();
		clickMouse(tab, MouseEvent.BUTTON1, p.x + 1, p.y + 1, 1, 0);
		assertEquals(programs[1], panel.getSelectedProgram());
		assertTrue(!startProgram.equals(panel.getSelectedProgram()));

		assertTrue(action.isEnabled());

		performAction(action, true);
		assertEquals(startProgram, panel.getSelectedProgram());
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

		assertEquals(Color.BLUE, getFieldPanelBackgroundColor(fp, BigInteger.ZERO));
		assertEquals(Color.WHITE, getFieldPanelBackgroundColor(fp, BigInteger.ONE));
		assertEquals(BigInteger.valueOf(4), fp.getCursorLocation().getIndex());

		Color lineColor = (Color) getInstanceField("CURSOR_LINE_COLOR", CodeBrowserPlugin.class);

		programManager.setCurrentProgram(p2);
		assertEquals(lineColor, getFieldPanelBackgroundColor(fp, BigInteger.ZERO));
		assertEquals(Color.WHITE, getFieldPanelBackgroundColor(fp, BigInteger.ONE));
		assertEquals(BigInteger.ZERO, fp.getCursorLocation().getIndex());

		programManager.setCurrentProgram(p1);
		assertEquals(Color.BLUE, getFieldPanelBackgroundColor(fp, BigInteger.ZERO));
		assertEquals(Color.WHITE, getFieldPanelBackgroundColor(fp, BigInteger.ONE));
		assertEquals(BigInteger.valueOf(4), fp.getCursorLocation().getIndex());
	}

	@Test
	public void testTabUpdate() throws Exception {
		Program p = openDummyProgram("login", true);

		// select second tab (the "login" program)
		panel = findComponent(tool.getToolFrame(), MultiTabPanel.class);

		// don't let focus issues hide the popup list
		panel.setIgnoreFocus(true);

		panel.setSelectedProgram(p);
		assertEquals(p, panel.getSelectedProgram());

		addComment(p);

		String oldName = p.getName();
		String newName = "myNewLogin";
		renameProgramFile(p, newName);
		ArrayList<DomainObjectChangeRecord> changeRecs = new ArrayList<>();
		changeRecs.add(
			new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RENAMED, oldName, p.getName()));
		DomainObjectChangedEvent ev = new DomainObjectChangedEvent(p, changeRecs);
		runSwing(() -> env.getPlugin(MultiTabPlugin.class).domainObjectChanged(ev));

		// Check the name on the tab and in the tooltip.
		JPanel tabPanel = getTabPanel(p);
		JLabel label = (JLabel) findComponentByName(tabPanel, "objectName");
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
		setFrameSize(500, 500);
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
		assertListWindowShowing();
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
		setFrameSize(500, 500);
		assertShowing(programs[2]);
		assertHidden(programs[3]);

		// select 'tms', which is the last tab before the list is shown
		selectTab(programs[2]);
		performNextAction();
		assertListWindowShowing();

		// the newly selected program should the first program, as the selection 
		// should have left the window and wrapped around 'notepad'
		performNextAction();
		assertProgramSelected(programs[0]);
		assertListWindowHidden();

		//
		// Now try the other direction, which should wrap back around the other direction,
		// showing the list, with another action to keep on moving.
		//		
		selectTab(programs[0]);// start off at the first tab	
		performPreviousAction();
		assertListWindowShowing();

		performPreviousAction();
		assertProgramSelected(programs[2]);// 'tms'--last visible program
		assertListWindowHidden();
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertProgramSelected(Program p) {
		Program selectedProgram = panel.getSelectedProgram();
		assertEquals(selectedProgram, p);
	}

	private void printResizeDebug() {
		//
		// To show the '>>' label, the number of tabs must exceed the room visible to show them
		//

		// frame size

		// available width
		int panelWidth = panel.getWidth();
		System.out.println("available width: " + panelWidth);

		// size label
		int totalWidth = 0;
		JComponent listLabel = (JComponent) getInstanceField("showHiddenListLabel", panel);
		System.out.println("label width: " + listLabel.getWidth());
		totalWidth = listLabel.getWidth();

		// size of each tab's panel
		Map<?, ?> map = (Map<?, ?>) getInstanceField("linkedProgramMap", panel);
		Collection<?> values = map.values();
		for (Object object : values) {
			JComponent c = (JComponent) object;
			totalWidth += c.getWidth();
			System.out.println("\t" + c.getWidth());
		}

		System.out.println("Total width: " + totalWidth + " out of " + panelWidth);
	}

	private void assertShowing(Program p) throws Exception {
		waitForConditionWithoutFailing(() -> {
			boolean isHidden = runSwing(() -> panel.isHidden(p));
			return !isHidden;
		});

		boolean isHidden = runSwing(() -> panel.isHidden(p));
		if (isHidden) {
			capture(tool.getToolFrame(), "multi.tabs.program2.should.be.showing");
		}

		assertFalse(runSwing(() -> panel.isHidden(p)));
	}

	private void assertHidden(Program p) {
		assertTrue(runSwing(() -> panel.isHidden(p)));
	}

	private void assertListWindowHidden() {
		Window listWindow = getListWindow();
		assertFalse(listWindow.isShowing());
	}

	private void assertListWindowShowing() {
		Window listWindow = getListWindow();
		assertTrue(listWindow.isShowing());
	}

	private MarkerSet createMarkers(final Program p) {
		final AtomicReference<MarkerSet> ref = new AtomicReference<>();
		runSwing(() -> ref.set(markerService.createPointMarker("Test", "Test", p, 40, false, false,
			true, Color.BLUE, null)));
		return ref.get();
	}

	private Window getListWindow() {
		Window window = windowForComponent(panel);
		ProgramListPanel listPanel = findComponent(window, ProgramListPanel.class, true);
		return windowForComponent(listPanel);
	}

	private Color getFieldPanelBackgroundColor(FieldPanel fp, BigInteger index) {
		return runSwing(() -> fp.getBackgroundColor(index));
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
		JPanel tab = panel.getTab(p);
		Point point = tab.getLocationOnScreen();
		clickMouse(tab, MouseEvent.BUTTON1, point.x + 1, point.y + 1, 1, 0);
		assertEquals(p, panel.getSelectedProgram());
	}

	private JPanel getTabPanel(final Program p) {

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
			p.getListing().setComment(p.getAddressFactory().getAddress("01000000"),
				CodeUnit.REPEATABLE_COMMENT, "This is a simple comment change.");
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

	private Program doOpenProgram(Program p, boolean makeCurrent) {
		int programState = makeCurrent ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE;
		pm.openProgram(p, programState);
		waitForSwing();
		panel = findComponent(tool.getToolFrame(), MultiTabPanel.class);

		// don't let focus issues hide the popup list
		panel.setIgnoreFocus(true);

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

	private ProgramListPanel showList() {
		JLabel listLabel = (JLabel) findComponentByName(panel, "showList");
		Point p = listLabel.getLocationOnScreen();
		clickMouse(listLabel, MouseEvent.BUTTON1, p.x + 3, p.y + 2, 1, 0);
		waitForSwing();
		Window window = windowForComponent(panel);
		ProgramListPanel listPanel = findComponent(window, ProgramListPanel.class, true);
		assertNotNull(listPanel);
		return listPanel;
	}

}
