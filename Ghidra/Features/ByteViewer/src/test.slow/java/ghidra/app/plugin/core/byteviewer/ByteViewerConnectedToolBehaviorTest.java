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
package ghidra.app.plugin.core.byteviewer;

import static org.junit.Assert.*;

import java.awt.Point;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.util.Date;

import org.junit.*;

import docking.ActionContext;
import docking.action.ToggleDockingAction;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.plugin.core.format.*;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for two byte viewers connected.
 */
public class ByteViewerConnectedToolBehaviorTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool toolOne;
	private PluginTool tool2;
	private Program program;
	private ByteViewerPlugin pluginOne;
	private ByteViewerPlugin plugin2;
	private ByteViewerPanel panelOne;
	private ByteViewerPanel panel2;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		toolOne = env.getTool();
		setUpTool(toolOne);
		pluginOne = env.getPlugin(ByteViewerPlugin.class);
		toolOne.showComponentProvider(pluginOne.getProvider(), true);
		panelOne = pluginOne.getProvider().getByteViewerPanel();

		tool2 = env.launchAnotherDefaultTool();
		setUpTool(tool2);
		plugin2 = getPlugin(tool2, ByteViewerPlugin.class);
		tool2.showComponentProvider(plugin2.getProvider(), true);
		panel2 = plugin2.getProvider().getByteViewerPanel();

		env.connectTools(toolOne, tool2);

		program = buildNotepad();
		final ProgramManager pm = toolOne.getService(ProgramManager.class);
		runSwing(() -> pm.openProgram(program.getDomainFile()));
	}

	private Program buildNotepad() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 0x2000);
		Program p = builder.getProgram();
		p.clearUndo();
		return p;
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testLocationChanges() throws Exception {
		// location changes should track
		// position at 01001004
		final FieldLocation loc = getFieldLocation(pluginOne, getAddr(0x01001004));
		runSwing(() -> {
			ByteViewerComponent c = panelOne.getCurrentComponent();
			//c.setCursorPosition(0, 4, 0, 0);
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});
		// verify that ByteViewer2 is at the same position
		ByteBlockInfo info2 = plugin2.getProvider().getCursorLocation();
		assertEquals(getAddr(0x01001004), convertToAddr(plugin2, info2));
	}

	@Test
	public void testSelectionChanges() throws Exception {
		// selection should track
		showTool(tool2);
		env.showTool();

		final ByteViewerComponent c = panelOne.getCurrentComponent();

		// choose code unit boundaries so that we can compare the
		// selection with the code browser's selection
		runSwing(() -> {
			FieldLocation loc = getFieldLocation(pluginOne, getAddr(0x01001004));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
			c.scrollToCursor();
		});

		Point startPoint = c.getCursorPoint();
		assertNotNull(startPoint);

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(pluginOne, getAddr(0x010010bb));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
			c.scrollToCursor();
		});
		Point endPoint = c.getCursorPoint();
		assertNotNull(endPoint);

		dragMouse(c, 1, startPoint.x, startPoint.y, endPoint.x, endPoint.y, 0);
		waitForPostedSwingRunnables();

		ByteBlockSelection selOne = c.getViewerSelection();

		ByteBlockSelection sel2 = panel2.getCurrentComponent().getViewerSelection();
		assertTrue(byteBlockSelectionEquals(selOne, sel2));

	}

	@Test
	public void testEdit() throws Exception {
		// make changes in one
		// verify the other tools shows the changes in red

		env.showTool();
		showTool(tool2);
		final ToggleDockingAction action =
			(ToggleDockingAction) getAction(pluginOne, "Enable/Disable Byteviewer Editing");
		final FieldLocation loc = getFieldLocation(pluginOne, getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent c = panelOne.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new ActionContext());
		});
		assertTrue(action.isSelected());
		final ByteViewerComponent c = panelOne.getCurrentComponent();
		assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR, c.getFocusedCursorColor());
		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();

		ByteViewerComponent c2 = panel2.getCurrentComponent();
		ByteField f2 = c2.getField(BigInteger.ZERO, 0);
		assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR, f2.getForeground());
	}

	@Test
	public void testUndoEdit() throws Exception {
		// make changes in one
		// verify the other tools shows the changes in red

		env.showTool();
		showTool(tool2);
		final ToggleDockingAction action =
			(ToggleDockingAction) getAction(pluginOne, "Enable/Disable Byteviewer Editing");
		final FieldLocation loc = getFieldLocation(pluginOne, getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent c = panelOne.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new ActionContext());
		});
		assertTrue(action.isSelected());
		final ByteViewerComponent c = panelOne.getCurrentComponent();
		assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR, c.getFocusedCursorColor());
		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();

		ByteViewerComponent c2 = panel2.getCurrentComponent();
		ByteField f2 = c2.getField(BigInteger.ZERO, 0);
		assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR, f2.getForeground());

		undo(program);

		f2 = c2.getField(BigInteger.ZERO, 0);
		assertNull(f2.getForeground());
	}

	private void setUpTool(PluginTool tool) throws Exception {
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(ByteViewerPlugin.class.getName());
	}

	private FieldLocation getFieldLocation(ByteViewerPlugin plugin, Address addr) {
		ByteViewerPanel panel = plugin.getProvider().getByteViewerPanel();
		ByteViewerComponent c = panel.getCurrentComponent();
		ProgramByteBlockSet blockset = (ProgramByteBlockSet) plugin.getProvider().getByteBlockSet();
		ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
		return c.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
	}

	private Address getAddr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private Address convertToAddr(ByteViewerPlugin plugin, ByteBlockInfo info) {
		return ((ProgramByteBlockSet) plugin.getProvider().getByteBlockSet()).getAddress(
			info.getBlock(), info.getOffset());
	}

	private boolean byteBlockSelectionEquals(ByteBlockSelection b1, ByteBlockSelection b2) {

		int nRanges = b1.getNumberOfRanges();
		if (nRanges != b2.getNumberOfRanges()) {
			return false;
		}
		for (int i = 0; i < nRanges; i++) {
			ByteBlockRange range1 = b1.getRange(i);
			ByteBlockRange range2 = b2.getRange(i);

			ByteBlock bb1 = range1.getByteBlock();
			ByteBlock bb2 = range2.getByteBlock();
			String start1 = bb1.getLocationRepresentation(range1.getStartIndex());
			String start2 = bb2.getLocationRepresentation(range2.getStartIndex());
			String end1 = bb1.getLocationRepresentation(range1.getEndIndex());
			String end2 = bb2.getLocationRepresentation(range2.getEndIndex());

			if (!start1.equals(start2) || !end1.equals(end2)) {
				return false;
			}
		}
		return true;
	}

}
