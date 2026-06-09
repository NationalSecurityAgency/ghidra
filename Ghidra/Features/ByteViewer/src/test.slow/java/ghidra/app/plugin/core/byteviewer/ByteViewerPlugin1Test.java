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
import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;

import org.junit.Test;

import docking.DefaultActionContext;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.format.*;
import ghidra.app.plugin.core.navigation.*;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

/**
 * Basic tests for the byte view plugin
 */
public class ByteViewerPlugin1Test extends AbstractByteViewerPluginTest {


	@Override
	protected List<Class<? extends Plugin>> getDefaultPlugins() {
		return List.of(NavigationHistoryPlugin.class, NextPrevAddressPlugin.class,
			CodeBrowserPlugin.class, GoToAddressLabelPlugin.class);
	}

	@Override
	protected Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 1000);
		builder.createMemory("mem1", "0xf0001300", 1000);

		// give us distinguishable bytes
		builder.setBytes("0x1001000", "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff");

		// ascii - "message"
		builder.setBytes("0x1001100", "message\0".getBytes(StandardCharsets.US_ASCII));
		builder.applyDataType("0x1001100", new StringDataType());

		return builder.getProgram();
	}

	@Test
	public void testOpenProgram() {
		assertEquals("Hex", panel.getCurrentComponent().getDataModel().getName());
		DockingActionIf action = provider.getOptionsAction();
		assertTrue(action.isEnabled());
		assertEquals(1, panel.getViewList().size());
	}

	@Test
	public void testOpenProgramNoMemory() throws Exception {
		tool.removePlugins(List.of(cbPlugin));

		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.closeProgram();
		});
		waitForSwing();

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		program = builder.getProgram();

		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
		});
		waitForSwing();

		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.closeProgram();
		});
		waitForSwing();

		program = buildProgram();
		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
		});
		waitForSwing();

		// no errors should occur
	}

	@Test
	public void testAddRemoveViews() throws Exception {
		loadViews("Chars", "Octal");

		assertEquals(3, panel.getViewList().size());

		List<String> names = panel.getViewNamesInDisplayOrder();
		assertEquals(3, names.size());
		Set<String> viewNames = new HashSet<>(names);
		assertTrue(viewNames.contains("Hex"));
		assertTrue(viewNames.contains("Octal"));
		assertTrue(viewNames.contains("Chars"));

		// verify cursor position is the same across all views
		// verify the view is visible
		ByteViewerComponent bc = findComponent(panel, "Hex");
		assertTrue(bc.isVisible());
		ByteBlockInfo bbInfo = bc.getViewerCursorLocation();

		bc = findComponent(panel, "Chars");
		assertTrue(bc.isVisible());
		assertEquals(bbInfo, bc.getViewerCursorLocation());

		bc = findComponent(panel, "Octal");
		assertTrue(bc.isVisible());
		assertEquals(bbInfo, bc.getViewerCursorLocation());

		enableViews(false, "Chars", "Hex");

		assertEquals(1, panel.getViewList().size());

		names = panel.getViewNamesInDisplayOrder();
		assertEquals(1, names.size());
		assertEquals("Octal", names.get(0));
	}

	@Test
	public void testSetSelection() throws Exception {
		loadViews("Chars", "Octal");

		final FieldSelection fsel = new FieldSelection();
		fsel.addRange(0, 0, 8, 7);

		ByteViewerComponent ascii = getView("Chars");
		setView(ascii);
		runSwing(() -> {
			ascii.selectionChanged(fsel, EventTrigger.GUI_ACTION);
		});

		ByteBlockSelection sel = ascii.getViewerSelection();

		ByteViewerComponent octal = getView("Octal");
		assertTrue(byteBlockSelectionEquals(sel, octal.getViewerSelection()));

		ProgramSelection psel = cbPlugin.getCurrentSelection();
		ByteBlockSelection bsel = panel.getViewerSelection();

		// convert bsel to an address set
		AddressSet set =
			((ProgramByteBlockSet) provider.getByteBlockSet()).getAddressSet(bsel);

		// subtract one address from code browser selection since it is on
		// a code unit boundary
		psel = new ProgramSelection(psel.subtract(new AddressSet(addr(0x01001087))));
		assertTrue(psel.hasSameAddresses(set));
	}

	@Test
	public void testSetSelectionWithMouse() throws Exception {

		loadViews("Chars", "Octal");

		ByteViewerComponent c = panel.getCurrentComponent();
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(addr(0x01001004));

		Point startPoint = c.getCursorPoint();

		goTo(addr(0x010010bc));
		Point endPoint = c.getCursorPoint();

		dragMouse(c, 1, startPoint.x, startPoint.y, endPoint.x, endPoint.y, 0);
		waitForSwing();

		ByteBlockSelection sel = c.getViewerSelection();
		ByteViewerComponent octal = findComponent(panel, "Octal");
		assertTrue(byteBlockSelectionEquals(sel, octal.getViewerSelection()));

		ProgramSelection psel = cbPlugin.getCurrentSelection();
		ByteBlockSelection bsel = panel.getViewerSelection();

		// convert bsel to an address set
		AddressSet set = ((ProgramByteBlockSet) provider.getByteBlockSet()).getAddressSet(bsel);
		assertTrue(psel.hasSameAddresses(set));
	}

	@Test
	public void testProcessSelectionEvent() throws Exception {
		loadViews("Chars", "Octal");

		ByteViewerComponent c = panel.getCurrentComponent();

		AddressSet set = new AddressSet();
		set.addRange(addr(0x01004178), addr(0x0100419b));
		set.addRange(addr(0x010041a8), addr(0x010041bc));
		ProgramSelection sel = new ProgramSelection(set);
		Plugin p = env.getPlugin(NavigationHistoryPlugin.class);
		p.firePluginEvent(new ProgramSelectionPluginEvent(p.getName(), sel, program));
		waitForSwing();

		ByteBlockSelection bsel = c.getViewerSelection();

		c = findComponent(panel, "Octal");
		assertTrue(byteBlockSelectionEquals(bsel, c.getViewerSelection()));
		c = findComponent(panel, "Chars");
		assertTrue(byteBlockSelectionEquals(bsel, c.getViewerSelection()));

		ProgramSelection psel = cbPlugin.getCurrentSelection();

		bsel = panel.getViewerSelection();

		// convert bsel to an address set
		set = ((ProgramByteBlockSet) provider.getByteBlockSet()).getAddressSet(bsel);
		assertTrue(psel.hasSameAddresses(set));
	}

	@Test
	public void testSetSelectionWithViews() throws Exception {
		final FieldSelection fsel = new FieldSelection();
		fsel.addRange(0, 0, 8, 7);

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			c.selectionChanged(fsel, EventTrigger.GUI_ACTION);
		});
		ByteViewerComponent c = panel.getCurrentComponent();
		ByteBlockSelection sel = c.getViewerSelection();
		loadViews("Chars", "Octal");
		// verify that the selections are the same after adding views
		ByteViewerComponent octalC = findComponent(panel, "Octal");
		assertTrue(byteBlockSelectionEquals(sel, octalC.getViewerSelection()));

		ByteViewerComponent asciiC = findComponent(panel, "Chars");
		assertTrue(byteBlockSelectionEquals(sel, asciiC.getViewerSelection()));

	}

	@Test
	public void testMultiRangeSelection() throws Exception {
		loadViews("Chars", "Octal");

		final FieldSelection fsel = new FieldSelection();
		fsel.addRange(0, 0, 4, 7);
		fsel.addRange(8, 0, 11, 7);
		fsel.addRange(18, 7, 22, 11);

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			c.selectionChanged(fsel, EventTrigger.GUI_ACTION);
		});
		ByteViewerComponent c = panel.getCurrentComponent();
		ByteBlockSelection sel = c.getViewerSelection();
		ByteViewerComponent octalC = findComponent(panel, "Octal");
		assertTrue(byteBlockSelectionEquals(sel, octalC.getViewerSelection()));

		ByteViewerComponent asciiC = findComponent(panel, "Chars");
		assertTrue(byteBlockSelectionEquals(sel, asciiC.getViewerSelection()));

	}

	@Test
	public void testLocationChanges() throws Exception {
		loadViews("Chars", "Octal");

		ByteViewerComponent c = panel.getCurrentComponent();

		goTo(addr(0x01001004));

		ByteBlockInfo info = c.getViewerCursorLocation();
		ByteViewerComponent ascii = getView("Chars");
		assertEquals(info, ascii.getViewerCursorLocation());
		ByteViewerComponent octal = getView("Octal");
		assertEquals(info, octal.getViewerCursorLocation());

		// convert to address
		Address addr = convertToAddr(info);
		assertEquals(addr(0x01001004), addr);

		assertEquals(addr, cbPlugin.getCurrentAddress());

		goTo(addr(0x01001081));

		info = c.getViewerCursorLocation();
		assertEquals(info, ascii.getViewerCursorLocation());
		assertEquals(info, octal.getViewerCursorLocation());

		// convert to addr
		addr = convertToAddr(info);
		assertEquals(addr(0x01001081), addr);
		// code browser will be on a code unit boundary
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
		assertEquals(cu.getMinAddress(), cbPlugin.getCurrentAddress());

		goTo(addr(0xf0001300));

		info = c.getViewerCursorLocation();
		assertEquals(info, ascii.getViewerCursorLocation());
		assertEquals(info, octal.getViewerCursorLocation());

		// convert to Address
		addr = convertToAddr(info);
		assertEquals(addr(0xf0001300L), addr);
		assertEquals(addr, cbPlugin.getCurrentAddress());
	}

	@Test
	public void testLocationChanges_RightArrow_HexToOctal() throws Exception {
		/*
		 	Test that each view tracks the main view correctly as the user uses the left/right
		 	arrow keys.  Each view has a different character count, which makes tracking a bit
		 	tricky.
		 	
		 	
		 	View		Hex              Octal
		 	
		 	Bytes 	47 4e 55 00   |    107 116 125 000
		 	Column  123456789..        123456789......
		 	
		 	Some examples:
		 	
		 	 	A) The user clicks in the 'Hex' view at column 4.
		 	 	   The 'Octal' view cursor will be placed at column 5.
		 	 	   
		 	 	   The user right-arrows.
		 	 	   The 'Hex' view is now at column 5.
		 	 	   The 'Octal' view is now at column 6.
		 	 	   
		 	 	   The user right-arrows.
		 	 	   The 'Hex' view is now at column 7.
		 	 	   The 'Octal' view is now at column 9.
		 	 	   
		 	 	   
		 	 	B) The user clicks the 'Octal' view at column 5.
		 	 	   The 'Hex' view is now at column 4.
		 	 	   
		 	 	   The user right-arrows.
		 	 	   The 'Octal' view is now at column 6.
		 	 	   The 'Hex' view is now at column 5.
		 	 	   
		 	 	   The user right-arrows.
		 	 	   The 'Octal' view is now at column 6.
		 	 	   The 'Hex' view is still at column 5.
		
		 */

		loadViews("Hex", "Octal");

		ByteViewerComponent hex = getView("Hex");
		ByteViewerComponent octal = getView("Octal");
		setView(hex);

		goTo(addr(0x01001004));
		assertPosition(hex, "44", 0);
		assertPosition(octal, "104", 0);

		rightArrow();
		assertPosition(hex, "44", 1);
		assertPosition(octal, "104", 1);

		rightArrow();
		assertPosition(hex, "55", 0);
		assertPosition(octal, "125", 0);
	}

	@Test
	public void testLocationChanges_RightArrow_OctalToHex() throws Exception {
		// see notes in testLocationChanges_RightArrow_HexToOctal

		loadViews("Hex", "Octal");

		ByteViewerComponent hex = getView("Hex");
		ByteViewerComponent octal = getView("Octal");
		setView(octal);

		goTo(addr(0x01001004));
		assertPosition(hex, "44", 0);
		assertPosition(octal, "104", 0);

		rightArrow();
		assertPosition(hex, "44", 1);
		assertPosition(octal, "104", 1);

		rightArrow();
		assertPosition(hex, "44", 1);    // this stayed the same, as it has not 3rd column to go to
		assertPosition(octal, "104", 2); // at 3rd column
	}

	@Test
	public void testLocationChanges_LeftArrow_OctalToHex() throws Exception {
		// see notes in testLocationChanges_RightArrow_HexToOctal

		loadViews("Hex", "Octal");

		ByteViewerComponent hex = getView("Hex");
		ByteViewerComponent octal = getView("Octal");
		setView(octal);

		goTo(addr(0x01001005));
		assertPosition(hex, "55", 0);
		assertPosition(octal, "125", 0);

		leftArrow();
		assertPosition(hex, "44", 1);    // end column; 2nd column, as it has not 3rd column 
		assertPosition(octal, "104", 2); // at 3rd column

		leftArrow();
		assertPosition(hex, "44", 1);    // stayed at end column  
		assertPosition(octal, "104", 1);

		leftArrow();
		assertPosition(hex, "44", 0);    // stayed at end column  
		assertPosition(octal, "104", 0);
	}

	@Test
	public void testLocationChanges_FromListing_WhenOnMnemonic() {

		loadViews("Hex");
		ByteViewerComponent hex = getView("Hex");

		// Address: 0x01001100
		// Mnemonic: ds
		// Operand: "message" 
		// Bytes: 6d 65 73 73 61 67 65 00

		goToOperand("0x01001100");
		assertPosition(hex, "6d", 0);
		assertListingPosition("\"message\"", 0);

		rightArrowListing();
		assertPosition(hex, "6d", 0); // no change
		assertListingPosition("\"message\"", 1);

		rightArrowListing();
		assertPosition(hex, "6d", 0); // no change
		assertListingPosition("\"message\"", 2);

		leftArrowListing();
		assertPosition(hex, "6d", 0); // no change
		assertListingPosition("\"message\"", 1);

		leftArrowListing();
		assertPosition(hex, "6d", 0); // no change
		assertListingPosition("\"message\"", 0);
	}

	@Test
	public void testBytesPerLinesChange() throws Exception {

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		runSwing(() -> d.setBytesPerLine(10));
		pressButtonByText(d.getComponent(), "OK");

		waitForSwing();

		// verify that the bytes per line is 10
		ByteViewerConfigOptions configOptions = provider.getConfigOptions();
		assertEquals(10, configOptions.getBytesPerLine());

		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(10, runSwing(() -> c.getNumberOfFields()).intValue());
	}

	@Test
	public void testOffsetChange() {
		goTo(addr(0x0100100b));

		int offsetOfAddr = 16 /* bytes_per_line*/ - (0x0100100b - 0x1001000); // == 5

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		runSwing(() -> d.setOffset(offsetOfAddr));
		pressButtonByText(d.getComponent(), "OK");

		// verify that offset label on the plugin shows the new offset
		assertOffsetInfo(5, "0100100b");

		assertFieldLocationInfo(addr(0x0100100b), 1, 0 /* first field of the row */);
		assertFieldLocationInfo(addr(0x0100102b), 3, 0 /* first field of the row */);
	}

	@Test
	public void testOffsetShiftViaToolbarButtonActions() {
		DockingAction shiftLeftAction = provider.getShiftLeftAction();
		DockingAction shiftRightAction = provider.getShiftRightAction();

		goTo(addr(0x0100100b));
		assertFieldLocationInfo(addr(0x0100100b), 0, 0xb);

		for (int i = 0; i < 0xb; i++) {
			runSwing(() -> shiftLeftAction.actionPerformed(new DefaultActionContext()));
			assertOffsetInfo(16 - i - 1, "0100100b");
			assertFieldLocationInfo(addr(0x0100100b), 1, 0xb - i - 1);
		}
		for (int i = 0xb - 1; i > 0; i--) {
			runSwing(() -> shiftRightAction.actionPerformed(new DefaultActionContext()));
			assertOffsetInfo(16 - i, "0100100b");
			assertFieldLocationInfo(addr(0x0100100b), 1, 0xb - i);
		}
	}

	@Test
	public void testSetGroupSize() throws Exception {

		ByteViewerComponent c = panel.getCurrentComponent();
		panel.setCurrentView(c); // force component to have focus
		assertEquals(16, runSwing(() -> c.getNumberOfFields()).intValue());

		goTo(addr(0x0100100b));

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();

		runSwing(() -> dialog.setHexGroupSize(2));
		pressButtonByText(dialog.getComponent(), "OK");

		DataFormatModel dataModel = c.getDataModel();
		if (!(dataModel instanceof HexFormatModel hexModel)) {
			fail();
			return;
		}
		assertEquals(2, runSwing(() -> hexModel.getHexGroupSize()).intValue());
		assertEquals(8, runSwing(() -> c.getNumberOfFields()).intValue());
	}

	@Test
	public void testReorderViews() throws Exception {
		loadViews("Chars", "Octal");

		List<String> names = panel.getViewNamesInDisplayOrder();
		assertEquals("Hex", names.get(0));
		assertEquals("Octal", names.get(1));
		assertEquals("Chars", names.get(2));

		final JTableHeader columnHeader = (JTableHeader) findContainer(panel, JTableHeader.class);
		// move column 3 to 2
		runSwing(() -> {
			TableColumnModel columnModel = columnHeader.getColumnModel();
			columnModel.moveColumn(3, 2);
		});

		names = panel.getViewNamesInDisplayOrder();
		assertEquals("Hex", names.get(0));
		assertEquals("Chars", names.get(1));
		assertEquals("Octal", names.get(2));

		// move column 2 to 1
		runSwing(() -> {
			TableColumnModel columnModel = columnHeader.getColumnModel();
			columnModel.moveColumn(2, 1);
		});
		names = panel.getViewNamesInDisplayOrder();
		assertEquals("Chars", names.get(0));
		assertEquals("Hex", names.get(1));
		assertEquals("Octal", names.get(2));

	}

	@Test
	public void testResizeViews() {
		loadViews("Chars", "Octal");
		assertNotEquals(200, getViewWidth("Chars"));

		setViewWidth("Chars", 200);

		assertEquals(200, panel.getViewWidth("Chars"));
	}

	@Test
	public void testResizeViewsSaveState() {
		loadViews("Chars", "Octal");
		assertNotEquals(200, getViewWidth("Chars"));

		setViewWidth("Chars", 200);
		env.saveRestoreToolState();

		assertEquals(200, panel.getViewWidth("Chars"));
	}

	@Test
	public void testReorderViewsSaveState() throws Exception {

		loadViews("Chars", "Octal");

		final JTableHeader columnHeader = (JTableHeader) findContainer(panel, JTableHeader.class);
		// move column 1 to 0
		runSwing(() -> {
			TableColumnModel columnModel = columnHeader.getColumnModel();
			columnModel.moveColumn(3, 2);
		});
		List<String> names = panel.getViewNamesInDisplayOrder();

		env.saveRestoreToolState();
		List<String> newNames = panel.getViewNamesInDisplayOrder();
		assertEquals(names, newNames);
	}

	@Test
	public void testShowingSnapshotDoesNotAddMultipleToolbarActions() {

		DockingActionIf cloneAction = getAction(plugin, "ByteViewer Clone");
		performAction(cloneAction);
		waitForSwing();
		assertOnlyOneProviderToolbarAction();

		performAction(cloneAction);
		waitForSwing();
		assertOnlyOneProviderToolbarAction();
	}

}
