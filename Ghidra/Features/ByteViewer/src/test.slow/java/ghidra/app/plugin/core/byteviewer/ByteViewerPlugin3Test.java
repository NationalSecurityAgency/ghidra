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
import java.util.List;

import javax.swing.SwingUtilities;

import org.junit.Test;

import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.format.ByteBlockInfo;
import ghidra.app.plugin.core.format.ByteBlockSelection;
import ghidra.app.plugin.core.navigation.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

/**
 * Tests for what the byte viewer should do and not when it is not visible.
 * 
 */
public class ByteViewerPlugin3Test extends AbstractByteViewerPluginTest {

	@Override
	protected List<Class<? extends Plugin>> getDefaultPlugins() {
		return List.of(GoToAddressLabelPlugin.class, NavigationHistoryPlugin.class,
			NextPrevAddressPlugin.class, CodeBrowserPlugin.class);
	}

	@Override
	protected Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 0x2000);
		Program p = builder.getProgram();
		p.clearUndo();
		return p;
	}


	@Test
    public void testSetVisible() throws Exception {

		goTo(addr(0x01001004));
		ByteViewerComponent c = panel.getCurrentComponent();
		ByteBlockInfo info = c.getViewerCursorLocation();
		assertEquals(cbPlugin.getCurrentAddress(), convertToAddr(info));

		// make a selection in the Code Browser
		Point startPoint = c.getCursorPoint();
		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr(0x010010bc));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
		});
		Point endPoint = c.getCursorPoint();

		dragMouse(c, 1, startPoint.x, startPoint.y, endPoint.x, endPoint.y, 0);
		waitForSwing();

		ProgramSelection psel = cbPlugin.getCurrentSelection();

		ByteBlockSelection bsel = panel.getViewerSelection();

		// convert bsel to an address set
		AddressSet set =
			((ProgramByteBlockSet) provider.getByteBlockSet()).getAddressSet(bsel);
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
		set = ((ProgramByteBlockSet) provider.getByteBlockSet()).getAddressSet(bsel);
		assertTrue(psel.hasSameAddresses(set));
	}

	@Test
    public void testNotVisible() throws Exception {
		Address addr = addr(0x01002000);
		goTo(addr);
		ByteViewerComponent c = panel.getCurrentComponent();
		ByteBlockInfo info = c.getViewerCursorLocation();
		assertEquals(cbPlugin.getCurrentAddress(), convertToAddr(info));

		showComponent(false);

		addr = addr(0x01002500);
		goTo(addr);
		showComponent(true);
		info = c.getViewerCursorLocation();
		assertEquals(addr, convertToAddr(info));
	}

	private void showComponent(boolean visible) throws Exception {
		SwingUtilities.invokeAndWait(() -> tool.showComponentProvider(provider, visible));
	}
}
