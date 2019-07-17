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
package ghidra.app.plugin.core.marker;

import static org.junit.Assert.*;

import java.awt.Point;
import java.awt.event.MouseEvent;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.cmd.data.CreateStructureCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.bookmark.BookmarkEditCmd;
import ghidra.app.plugin.core.bookmark.BookmarkPlugin;
import ghidra.app.plugin.core.clear.ClearDialog;
import ghidra.app.plugin.core.clear.ClearPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.plugin.core.highlight.SetHighlightPlugin;
import ghidra.app.plugin.core.misc.MyProgramChangesDisplayPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.OverviewProvider;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;
import ghidra.util.Msg;

public class MarkerTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private DockingActionIf clearAction;
	private DockingActionIf clearWithOptionsAction;
	private MarkerService markerService;
	private CodeViewerService codeViewerService;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.showTool();
		setupTool(tool);

		cb = env.getPlugin(CodeBrowserPlugin.class);
		loadProgram("notepad");
		env.showTool();
		markerService = tool.getService(MarkerService.class);
		codeViewerService = tool.getService(CodeViewerService.class);
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(DisassemblerPlugin.class.getName());
		tool.addPlugin(ClearPlugin.class.getName());
		tool.addPlugin(SetHighlightPlugin.class.getName());
		tool.addPlugin(MyProgramChangesDisplayPlugin.class.getName());

		ClearPlugin cp = getPlugin(tool, ClearPlugin.class);
		clearAction = getAction(cp, "Clear Code Bytes");
		clearWithOptionsAction = getAction(cp, "Clear With Options");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		builder.setBytes("0x010032d7",
			"53 56 8b 74 24 18 33 db 8d 04 b6 c1 e0 04 66 39 98 60 8f 00 01", true);

		builder.setRecordChanges(true); // to trigger changed bookmarks
		program = builder.getProgram();

		final ProgramManager pm = tool.getService(ProgramManager.class);
		SwingUtilities.invokeAndWait(() -> pm.openProgram(program.getDomainFile()));
		builder.dispose();
		addrFactory = program.getAddressFactory();
	}

	private void waitForBookmarkUpdate() {
		program.flushEvents();
		waitForProgram(program);
	}

	@Test
	public void testCursorMarker() {

		waitForPostedSwingRunnables();
		assertTrue(cb.goToField(addr("0x100485c"), "Address", 0, 0));

		MarkerSet set = markerService.getMarkerSet("Cursor", program);
		assertTrue(set.getPriority() > MarkerService.HIGHLIGHT_PRIORITY);
		AddressSet addrSet = getAddresses(set);
		assertEquals(1, addrSet.getNumAddresses());
		assertEquals(addr("0x100485c"), addrSet.getMinAddress());

	}

	private void setSelection(FieldPanel fp, FieldSelection sel) {
		fp.setSelection(sel);
		Class<?>[] argClasses = new Class<?>[] { EventTrigger.class };
		Object[] args = new Object[] { EventTrigger.GUI_ACTION };
		runSwing(() -> invokeInstanceMethod("notifySelectionChanged", fp, argClasses, args));
	}

	@Test
	public void testSelectionMarker() {
		MarkerSet ms = markerService.getMarkerSet("Selection", program);
		assertEquals(0, getAddresses(ms).getNumAddresses());

		FieldPanel fp = cb.getFieldPanel();
		assertTrue(cb.goToField(addr("0x10032d2"), "Bytes", 0, 4));
		FieldLocation p1 = fp.getCursorLocation();
		assertTrue(cb.goToField(addr("0x10032d8"), "Address", 0, 0, 2));
		FieldLocation p2 = fp.getCursorLocation();
		FieldSelection sel = new FieldSelection();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		ms = markerService.getMarkerSet("Selection", program);
		AddressSet set = getAddresses(ms);
		assertEquals(7, set.getNumAddresses());
		assertEquals(addr("0x10032d2"), set.getMinAddress());
		assertEquals(addr("0x10032d8"), set.getMaxAddress());

		assertTrue(cb.goToField(addr("0x100e423"), "Bytes", 0, 4));
		p1 = fp.getCursorLocation();
		assertTrue(cb.goToField(addr("0x100e426"), "Address", 0, 0, 2, false));
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		set = getAddresses(ms);
		assertEquals(11, set.getNumAddresses());
		assertEquals(addr("0x10032d2"), set.getMinAddress());
		assertEquals(addr("0x100e426"), set.getMaxAddress());

		assertTrue(cb.goToField(addr("0x1001000"), "Address", 0, 0));
		setSelection(fp, new FieldSelection());

		set = getAddresses(ms);
		assertEquals(0, set.getNumAddresses());
	}

	@Test
	public void testSelectionMarkerNavigation() throws Exception {

		FieldPanel fp = cb.getFieldPanel();

		assertTrue(cb.goToField(addr("0x1001000"), "Bytes", 0, 4));
		FieldLocation p1 = fp.getCursorLocation();
		assertTrue(cb.goToField(addr("0x1001014"), "Address", 0, 0, 2));
		FieldLocation p2 = fp.getCursorLocation();
		FieldSelection sel = new FieldSelection();
		sel.addRange(p1, p2);

		assertTrue(cb.goToField(addr("0x10032d2"), "Bytes", 0, 4));
		p1 = fp.getCursorLocation();
		assertTrue(cb.goToField(addr("0x10032d8"), "Address", 0, 0, 2));
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		assertTrue(cb.goToField(addr("0xf0001315"), "Bytes", 0, 4));
		p1 = fp.getCursorLocation();
		assertTrue(cb.goToField(addr("0xf000131b"), "Address", 0, 0, 2));
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		setSelection(fp, sel);

		MarkerManager mm = (MarkerManager) markerService;
		OverviewProvider op = mm.getOverviewProvider();
		JPanel navPanel = (JPanel) op.getComponent();

		waitForProgram(program);

		clickMouse(navPanel, 1, 0, 0, 1, 0);

		assertEquals(addr("0x1001000"), cb.getCurrentAddress());

		clickMouse(navPanel, 1, 0, navPanel.getHeight() - MarkerSetImpl.MARKER_HEIGHT, 1, 0);
		assertEquals(addr("0xf0001315"), cb.getCurrentAddress());

		AddressIndexMap map = codeViewerService.getAddressIndexMap();
		int index = map.getIndex(addr("0x10032d4")).intValue();

		double ratio = (double) navPanel.getHeight() / map.getIndexCount().intValue();
		int pixel = (int) (index * ratio);

		clickMouse(navPanel, 1, 0, pixel, 1, 0);
		assertEquals(addr("0x10032d2"), cb.getCurrentAddress());

	}

	@Test
	public void testHighlightMarker() throws Exception {

		FieldPanel fp = cb.getFieldPanel();

		assertTrue(cb.goToField(addr("0x1001000"), "Bytes", 0, 4));
		FieldLocation p1 = fp.getCursorLocation();
		assertTrue(cb.goToField(addr("0x1001014"), "Address", 0, 0, 2));
		FieldLocation p2 = fp.getCursorLocation();
		FieldSelection sel = new FieldSelection();
		sel.addRange(p1, p2);

		assertTrue(cb.goToField(addr("0x10032d2"), "Bytes", 0, 4));
		p1 = fp.getCursorLocation();
		assertTrue(cb.goToField(addr("0x10032d8"), "Address", 0, 0, 2));
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		assertTrue(cb.goToField(addr("0xf0001315"), "Bytes", 0, 4));
		p1 = fp.getCursorLocation();
		assertTrue(cb.goToField(addr("0xf000131b"), "Address", 0, 0, 2));
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		setSelection(fp, sel);

		DockingActionIf a = getAction(getPlugin(tool, SetHighlightPlugin.class),
			"Set Highlight From Selection");
		performAction(a, cb.getProvider(), true);

		cb.goToField(addr("0x1001000"), "Address", 0, 0);
		setSelection(fp, new FieldSelection());

		MarkerSet ms = markerService.getMarkerSet("Highlight", program);
		AddressSet set = getAddresses(ms);
		assertEquals(35, set.getNumAddresses());

		assertEquals(addr("0x1001000"), set.getMinAddress());
	}

	private AddressSet getAddresses(MarkerSet ms) {
		return runSwing(() -> ms.getAddressSet());
	}

	@Test
	public void testPointMarkers() throws Exception {
		tool.addPlugin(BookmarkPlugin.class.getName());
		removeAllBookmarks();
		BookmarkEditCmd cmd = new BookmarkEditCmd(addr("0x1001000"), "Note", "TEST", "comment");
		applyCmd(program, cmd);

		cmd = new BookmarkEditCmd(addr("0x10032d2"), "Note", "TEST", "comment");
		applyCmd(program, cmd);

		cmd = new BookmarkEditCmd(addr("0xf000131b"), "Note", "TEST", "comment");
		applyCmd(program, cmd);

		waitForPostedSwingRunnables();
		MarkerSet set = markerService.getMarkerSet("Note Bookmarks", program);
		AddressSet addrSet = getAddresses(set);
		assertEquals(3, addrSet.getNumAddresses());
		assertEquals(addr("0x1001000"), addrSet.getMinAddress());
		assertTrue(addrSet.contains(addr("0x10032d2")));
		assertTrue(addrSet.contains(addr("0xf000131b")));

		MarkerManager mm = (MarkerManager) markerService;
		OverviewProvider op = mm.getOverviewProvider();
		JPanel navPanel = (JPanel) op.getComponent();

		waitForProgram(program);

		clickMouse(navPanel, 1, 0, 0, 1, 0);
		waitForProgram(program);

		assertEquals(addr("0x1001000"), cb.getCurrentAddress());

		clickMouse(navPanel, 1, 0, navPanel.getHeight() - MarkerSetImpl.MARKER_HEIGHT, 1, 0);
		waitForProgram(program);
		assertEquals(addr("0xf000131b"), cb.getCurrentAddress());

		AddressIndexMap map = codeViewerService.getAddressIndexMap();
		int index = map.getIndex(addr("0x10032d2")).intValue();

		double ratio = (double) navPanel.getHeight() / map.getIndexCount().intValue();
		int pixel = (int) (index * ratio);

		clickMouse(navPanel, 1, 0, pixel, 1, 0);
		assertEquals(addr("0x10032d2"), cb.getCurrentAddress());

		DockingActionIf action = getAction(cb, "Select All");
		performAction(action, cb.getProvider(), true);

		clickMouse(navPanel, 1, 0, navPanel.getHeight() - MarkerSetImpl.MARKER_HEIGHT, 1, 0);
		assertEquals(addr("0xf000131b"), cb.getCurrentAddress());
	}

	@Test
	public void testToolTip() throws Exception {
		tool.addPlugin(BookmarkPlugin.class.getName());
		cb.goToField(addr("0x10032d2"), "Address", 0, 0);

		BookmarkEditCmd cmd = new BookmarkEditCmd(addr("0x10032d9"), "Note", "TEST", "comment");
		applyCmd(program, cmd);

		waitForBookmarkUpdate();

		ProgramSelection selection = new ProgramSelection(addr("0x10032d8"), addr("0x10032df"));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", selection, program));

		final ActionContext context = cb.getProvider().getActionContext(null);
		runSwing(() -> clearAction.actionPerformed(context));
		waitForBusyTool(tool); // allow background clear command to complete

		waitForSwing();

		cb.goToField(addr("0x10032d9"), "Address", 0, 4);

		int x = 1;
		int y = getCursorOffset();
		long time = System.currentTimeMillis();
		MouseEvent dummyEvent =
			new MouseEvent(cb.getFieldPanel(), (int) time, time, 0, x, y, 1, false);
		MarkerManager mm = (MarkerManager) markerService;
		String tooltip = runSwing(() -> mm.generateToolTip(dummyEvent));
		assertEquals(
			"<html><font size=\"4\">Cursor<BR>Note [TEST]: comment<BR>Changes: Unsaved<BR>",
			tooltip);

	}

	private int getCursorOffset() {
		FieldPanel fp = cb.getFieldPanel();
		return fp.getCursorOffset();
	}

	@Test
	public void testToolTipMaxLines() throws Exception {
		tool.addPlugin(BookmarkPlugin.class.getName());
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		Address a = addr("0x0100b6db");
		for (int i = 0; i < 20; i++) {
			addCmd.add(new BookmarkEditCmd(a, "Type1", "Cat1a", "Cmt1A_" + (i + 1)));
			a = a.add(1);
		}

		if (!applyCmd(program, addCmd)) {
			Assert.fail("Could not create bookmarks - " + addCmd.getStatusMsg());
		}

		//make a structure
		CreateStructureCmd cmd = new CreateStructureCmd(addr("0100b6db"), 20);
		applyCmd(program, cmd);
		program.flushEvents();
		waitForPostedSwingRunnables();

		MarkerManager mm = (MarkerManager) markerService;

		cb.goToField(addr("0x100b6db"), "Address", 0, 4);

		Point cursor = cb.getListingPanel().getCursorPoint();

		int x = 1;
		int y = cursor.y;
		MouseEvent dummyEvent = new MouseEvent(cb.getFieldPanel(), (int) System.currentTimeMillis(),
			System.currentTimeMillis(), 0, x, y, 1, false);

		// debug
		ProgramLocation location = cb.getListingPanel().getProgramLocation(dummyEvent.getPoint());
		Msg.debug(this, "location for point: " + location + "; at " + location.getAddress());

		String tooltip = runSwing(() -> mm.generateToolTip(dummyEvent));
		assertNotNull("No tooltip for field: " + cb.getCurrentField() + "\n\tat address: " +
			cb.getCurrentAddress(), tooltip);

		// should have a line for "Cursor" and comments 1 through 9 for a max of 10 lines
		String expected = "<html><font size=\"4\">Cursor<BR>Type1 [Cat1a]: Cmt1A_1<BR>";
		assertTrue("Expected text to start with:\n\t" + expected + "\nfound:\n\t" + tooltip,
			tooltip.startsWith(expected));

		expected = "Type1 [Cat1a]: Cmt1A_9<BR>...<BR>";
		assertTrue("Expected text to end with:\n\t" + expected + "\nfound:\n\t" + tooltip,
			tooltip.endsWith(expected));
	}

	private void removeAllBookmarks() {
		DockingActionIf action = getAction(cb, "Select All");
		performAction(action, cb.getProvider(), true);
		performAction(clearWithOptionsAction, cb.getProvider(), false);
		final ClearDialog cd = env.waitForDialogComponent(ClearDialog.class, 500);

		JCheckBox commentsCheckBox = (JCheckBox) getInstanceField("commentsCb", cd);
		commentsCheckBox.setSelected(false);

		turnOffOption("Properties", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Code", cd);
		turnOffOption("Symbols", cd);

		runSwing(() -> cd.okCallback());
		waitForBusyTool(tool);

	}

	private void turnOffOption(String name, DialogComponentProvider dialog) {
		JCheckBox check = (JCheckBox) findAbstractButtonByText(dialog.getComponent(), name);
		check.setSelected(false);
	}
}
