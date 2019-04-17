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
package ghidra.app.plugin.debug.propertymanager;

import static org.junit.Assert.*;

import java.awt.Rectangle;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.DockingWindowManager;
import docking.action.DockingActionIf;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * PropertyManagerPluginTest
 */
public class PropertyManagerPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private MarkerService markerService;
	private AddressFactory addrFactory;
	private Program program;

	private PropertyManagerPlugin plugin;
	private JTable table;
	private PropertyManagerTableModel model;
	private PropertyManagerProvider provider;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.showTool();
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		tool.addPlugin(PropertyManagerPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		plugin = env.getPlugin(PropertyManagerPlugin.class);

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test", "0x01001000", 0x100);
		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();

		// Remove all existing bookmarks
		PropertyDeleteCmd delCmd = new PropertyDeleteCmd("Space", null);
		applyCmd(program, delCmd);

		// Add specific bookmarks

		int id = program.startTransaction("AddingProperties");
		try {
			Listing listing = program.getListing();
			CodeUnit codeUnit = listing.getCodeUnitAt(addr("01001010"));
			codeUnit.setProperty("Type1", 1);
			codeUnit = listing.getCodeUnitAt(addr("01001020"));
			codeUnit.setProperty("Type1", 2);
			codeUnit = listing.getCodeUnitAt(addr("01001030"));
			codeUnit.setProperty("Type1", 3);

			codeUnit = listing.getCodeUnitAt(addr("01001020"));
			codeUnit.setProperty("Type2", "Str1");
			codeUnit = listing.getCodeUnitAt(addr("01001040"));
			codeUnit.setProperty("Type2", "Str2");

			codeUnit = listing.getCodeUnitAt(addr("01001010"));
			codeUnit.setProperty("Type3");
			codeUnit = listing.getCodeUnitAt(addr("01001020"));
			codeUnit.setProperty("Type3");
			codeUnit = listing.getCodeUnitAt(addr("01001050"));
			codeUnit.setProperty("Type3");
		}
		finally {
			program.endTransaction(id, true);
		}

		provider = plugin.getPropertyViewProvider();
		SwingUtilities.invokeLater(() -> tool.showComponentProvider(provider, true));
		waitForPostedSwingRunnables();

		DockingWindowManager winMgr = DockingWindowManager.getActiveInstance();
		waitForComponentProvider(winMgr.getActiveWindow(), PropertyManagerProvider.class, 2000);

		table = (JTable) getInstanceField("table", provider);

		TableModel tm = table.getModel();
		assertTrue(tm instanceof PropertyManagerTableModel);
		model = (PropertyManagerTableModel) tm;

		markerService = tool.getService(MarkerService.class);
		assertNotNull(markerService);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();

	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Test
	public void testViewWithoutSelection() {

		assertEquals(3, model.getRowCount());
		assertEquals("Type1", model.getValueAt(0, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));
		assertEquals("Type2", model.getValueAt(1, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));
		assertEquals("Type3", model.getValueAt(2, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));

		MarkerSet markerSet =
			markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		assertNull(markerSet);

		Rectangle r = table.getCellRect(0, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);

		// No selection yet - verify no popup action
		clickMouse(table, MouseEvent.BUTTON3, r.x, r.y, 1, 0, true);
		waitForPostedSwingRunnables();
		DockingActionIf deleteAction =
			getAction(plugin, PropertyManagerProvider.DELETE_PROPERTIES_ACTION_NAME);

		// Select Type1
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(0, table.getSelectedRow());

		// Verify marker set
		markerSet = markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		AddressSet addrs = new AddressSet(getAddresses(markerSet));
		Address a = addr("01001010");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001020");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001030");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Select Type2
		r = table.getCellRect(1, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(1, table.getSelectedRow());

		// Verify marker set
		markerSet = markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		addrs = new AddressSet(getAddresses(markerSet));
		a = addr("01001020");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001040");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Select Type3
		r = table.getCellRect(2, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(2, table.getSelectedRow());

		// Verify marker set
		markerSet = markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		addrs = new AddressSet(getAddresses(markerSet));
		a = addr("01001010");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001020");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001050");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Verify popup action
		MouseEvent e = new MouseEvent(table, MouseEvent.MOUSE_PRESSED, System.currentTimeMillis(),
			0, r.x, r.y, 1, false, MouseEvent.BUTTON3);
		clickMouse(table, MouseEvent.BUTTON3, r.x, r.y, 1, 0, true);
		waitForPostedSwingRunnables();
		assertTrue(
			deleteAction.isEnabledForContext(plugin.getPropertyViewProvider().getActionContext(e)));

	}

	private void makeSelection(String from, String to) {

		ProgramSelection sel = new ProgramSelection(addr(from), addr(to));

		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr(from)), program));

	}

	private void clearSelection() {
		ProgramSelection sel = new ProgramSelection();
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));
	}

	@Test
	public void testViewWithSelection() throws Exception {

		makeSelection("01001031", "01001040");

		waitForUpdateTimer();
		waitForPostedSwingRunnables();

		assertEquals(1, model.getRowCount());
		assertEquals("Type2", model.getValueAt(0, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));

		// Select Type2
		Rectangle r = table.getCellRect(0, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(0, table.getSelectedRow());
		MarkerSet markerSet =
			markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);

		// Verify marker set
		AddressSet addrs = new AddressSet(getAddresses(markerSet));
		Address a = addr("01001040");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Verify popup action
		DockingActionIf deleteAction =
			getAction(plugin, PropertyManagerProvider.DELETE_PROPERTIES_ACTION_NAME);
		MouseEvent e = new MouseEvent(table, MouseEvent.MOUSE_PRESSED, System.currentTimeMillis(),
			0, r.x, r.y, 1, false, MouseEvent.BUTTON3);
		clickMouse(table, MouseEvent.BUTTON3, r.x, r.y, 1, 0, true);
		waitForPostedSwingRunnables();
		assertTrue(
			deleteAction.isEnabledForContext(plugin.getPropertyViewProvider().getActionContext(e)));

	}

	private void waitForUpdateTimer() {
		Timer timer = (Timer) getInstanceField("updateTimer", plugin);
		while (timer.isRunning()) {
			try {
				Thread.sleep(100);
			}
			catch (InterruptedException e) {
				// don't care, will try again
			}
		}
	}

	private AddressSet getAddresses(MarkerSet ms) {
		return runSwing(() -> ms.getAddressSet());
	}

	@Test
	public void testDeleteActionWithoutSelection() {

		testViewWithoutSelection();

		DockingActionIf deleteAction =
			getAction(plugin, PropertyManagerProvider.DELETE_PROPERTIES_ACTION_NAME);
		performAction(deleteAction, true);

		// Property Type3 should no longer exist
		assertNull(program.getUsrPropertyManager().getPropertyMap("Type3"));

		assertEquals(2, model.getRowCount());
		assertEquals("Type1", model.getValueAt(0, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));
		assertEquals("Type2", model.getValueAt(1, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));

		MarkerSet markerSet =
			markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		assertNotNull(markerSet);
		AddressSet addrs = getAddresses(markerSet);
		assertTrue(addrs.isEmpty());

		Rectangle r = table.getCellRect(0, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);

		// No selection yet - verify no popup action
		clickMouse(table, MouseEvent.BUTTON3, r.x, r.y, 1, 0, true);
		waitForPostedSwingRunnables();
		// Select Type1
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(0, table.getSelectedRow());

		// Verify marker set
		markerSet = markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		addrs = new AddressSet(getAddresses(markerSet));
		Address a = addr("01001010");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001020");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001030");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Select Type2
		r = table.getCellRect(1, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(1, table.getSelectedRow());

		// Verify marker set
		markerSet = markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		addrs = new AddressSet(getAddresses(markerSet));
		a = addr("01001020");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001040");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Verify popup action
		clickMouse(table, MouseEvent.BUTTON3, r.x, r.y, 1, 0, true);
		waitForPostedSwingRunnables();

	}

	@Test
	public void testDeleteActionWithSelection() throws Exception {

		testViewWithSelection();

		DockingActionIf deleteAction =
			getAction(plugin, PropertyManagerProvider.DELETE_PROPERTIES_ACTION_NAME);
		performAction(deleteAction, true);

		PropertyMap map = program.getUsrPropertyManager().getPropertyMap("Type2");
		assertNotNull(map);
		assertTrue(map.hasProperty(addr("01001020")));
		assertTrue(!map.hasProperty(addr("01001040")));

		assertEquals(0, model.getRowCount());

		MarkerSet markerSet =
			markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		assertNotNull(markerSet);
		AddressSet addrs = getAddresses(markerSet);
		assertTrue(addrs.isEmpty());

		clearSelection();
		waitForUpdateTimer();
		waitForPostedSwingRunnables();

		assertEquals(3, model.getRowCount());
		assertEquals("Type1", model.getValueAt(0, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));
		assertEquals("Type2", model.getValueAt(1, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));
		assertEquals("Type3", model.getValueAt(2, PropertyManagerTableModel.PROPERTY_NAME_COLUMN));

		table.clearSelection();
		waitForPostedSwingRunnables();

		addrs = getAddresses(markerSet);
		assertTrue(addrs.isEmpty());

		Rectangle r = table.getCellRect(0, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);

		// No selection yet - verify no popup action
		clickMouse(table, MouseEvent.BUTTON3, r.x, r.y, 1, 0, true);
		waitForPostedSwingRunnables();

		// Select Type1
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(0, table.getSelectedRow());

		// Verify marker set
		markerSet = markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		addrs = new AddressSet(getAddresses(markerSet));
		Address a = addr("01001010");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001020");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001030");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Select Type2
		r = table.getCellRect(1, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(1, table.getSelectedRow());

		// Verify marker set
		markerSet = markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		addrs = new AddressSet(getAddresses(markerSet));
		a = addr("01001020");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Select Type3
		r = table.getCellRect(2, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, false);
		clickMouse(table, MouseEvent.BUTTON1, r.x, r.y, 1, 0, false);
		waitForPostedSwingRunnables();
		assertEquals(2, table.getSelectedRow());

		// Verify marker set
		markerSet = markerService.getMarkerSet(PropertyManagerPlugin.PROPERTY_MARKER_NAME, program);
		addrs = new AddressSet(getAddresses(markerSet));
		a = addr("01001010");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001020");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		a = addr("01001050");
		assertTrue(addrs.contains(a));
		addrs.deleteRange(a, a);
		assertTrue(addrs.isEmpty());

		// Verify popup action
		MouseEvent e = new MouseEvent(table, MouseEvent.MOUSE_PRESSED, System.currentTimeMillis(),
			0, r.x, r.y, 1, false, MouseEvent.BUTTON3);
		clickMouse(table, MouseEvent.BUTTON3, r.x, r.y, 1, 0, true);
		waitForPostedSwingRunnables();
		assertTrue(
			deleteAction.isEnabledForContext(plugin.getPropertyViewProvider().getActionContext(e)));

	}

}
