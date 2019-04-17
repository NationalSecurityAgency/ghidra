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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.awt.Point;

import javax.swing.SwingUtilities;

import org.junit.*;

import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.format.ByteBlockInfo;
import ghidra.app.plugin.core.format.ByteBlockSelection;
import ghidra.app.plugin.core.navigation.*;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for what the byte viewer should do and not when it is not visible.
 * 
 */
public class ByteViewerPlugin3Test extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private ByteViewerPlugin plugin;
	private ByteViewerPanel panel;
	private CodeBrowserPlugin cbPlugin;

	/**
	 * Constructor for ByteViewerPlugin4Test.
	 * @param arg0
	 */
	public ByteViewerPlugin3Test() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
    @Before
    public void setUp() throws Exception {
		env = new TestEnv();
		try {
			tool = env.getTool();
			tool.addPlugin(GoToAddressLabelPlugin.class.getName());
			tool.addPlugin(NavigationHistoryPlugin.class.getName());
			tool.addPlugin(NextPrevAddressPlugin.class.getName());
			tool.addPlugin(CodeBrowserPlugin.class.getName());

			tool.addPlugin(ByteViewerPlugin.class.getName());

			plugin = env.getPlugin(ByteViewerPlugin.class);
			tool.showComponentProvider(plugin.getProvider(), true);
			cbPlugin = env.getPlugin(CodeBrowserPlugin.class);

			program = buildNotepad();
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
			panel = plugin.getProvider().getByteViewerPanel();
			waitForPostedSwingRunnables();
			env.showTool();

		}
		catch (Exception e) {
			env.dispose();
			throw e;
		}
	}

	private Program buildNotepad() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 0x2000);
		Program p = builder.getProgram();
		p.clearUndo();
		return p;
	}

	/*
	 * @see TestCase#tearDown()
	 */
    @After
    public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

@Test
    public void testSetVisible() throws Exception {

		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(getAddr(0x01001004));
		final ByteViewerComponent c = panel.getCurrentComponent();
		ByteBlockInfo info = c.getViewerCursorLocation();
		assertEquals(cbPlugin.getCurrentAddress(), convertToAddr(info));

		// make a selection in the Code Browser
		Point startPoint = c.getCursorPoint();
		SwingUtilities.invokeAndWait(new Runnable() {
			@Override
			public void run() {
				FieldLocation loc = getFieldLocation(getAddr(0x010010bc));
				c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
			}
		});
		Point endPoint = c.getCursorPoint();

		dragMouse(c, 1, startPoint.x, startPoint.y, endPoint.x, endPoint.y, 0);
		waitForPostedSwingRunnables();

		ProgramSelection psel = cbPlugin.getCurrentSelection();

		ByteBlockSelection bsel = panel.getViewerSelection();

		// convert bsel to an address set
		AddressSet set =
			((ProgramByteBlockSet) plugin.getProvider().getByteBlockSet()).getAddressSet(bsel);
		assertTrue(psel.hasSameAddresses(set));

		info = c.getViewerCursorLocation();

		// hide the byte viewer
		showComponent(false);

		// show the byte viewer
		showComponent(true);

		// the location and selection should be intact
		CodeUnit cu = program.getListing().getCodeUnitContaining(convertToAddr(info));
		assertEquals(cbPlugin.getCurrentAddress(), cu.getMinAddress());

		psel = cbPlugin.getCurrentSelection();

		bsel = panel.getViewerSelection();

		// convert bsel to an address set
		set = ((ProgramByteBlockSet) plugin.getProvider().getByteBlockSet()).getAddressSet(bsel);
		assertTrue(psel.hasSameAddresses(set));
	}

@Test
    public void testNotVisible() throws Exception {
		GoToService goToService = tool.getService(GoToService.class);
		Address addr = getAddr(0x01002000);
		goToService.goTo(addr);
		final ByteViewerComponent c = panel.getCurrentComponent();
		ByteBlockInfo info = c.getViewerCursorLocation();
		assertEquals(cbPlugin.getCurrentAddress(), convertToAddr(info));

		showComponent(false);

		addr = getAddr(0x01002500);
		goToService.goTo(addr);
		showComponent(true);
		info = c.getViewerCursorLocation();
		assertEquals(addr, convertToAddr(info));
	}

	private Address getAddr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private Address convertToAddr(ByteBlockInfo info) {
		return ((ProgramByteBlockSet) plugin.getProvider().getByteBlockSet()).getAddress(
			info.getBlock(), info.getOffset());
	}

	private FieldLocation getFieldLocation(Address addr) {
		ByteViewerComponent c = panel.getCurrentComponent();
		ProgramByteBlockSet blockset = (ProgramByteBlockSet) plugin.getProvider().getByteBlockSet();
		ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
		return c.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
	}

	private void showComponent(final boolean visible) throws Exception {
		SwingUtilities.invokeAndWait(new Runnable() {
			@Override
			public void run() {
				tool.showComponentProvider(plugin.getProvider(), visible);
			}
		});
	}
}
