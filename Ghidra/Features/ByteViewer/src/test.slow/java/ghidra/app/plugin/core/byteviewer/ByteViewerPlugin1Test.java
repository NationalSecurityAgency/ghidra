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

import java.awt.*;
import java.math.BigInteger;
import java.util.*;
import java.util.List;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.event.TableColumnModelEvent;

import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.menu.ToolBarItemManager;
import docking.menu.ToolBarManager;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.format.*;
import ghidra.app.plugin.core.navigation.*;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.AddressInput;
import ghidra.app.util.bean.FixedBitSizeValueField;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Basic tests for the byte view plugin
 */
public class ByteViewerPlugin1Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private ByteViewerPlugin plugin;
	private ByteViewerPanel panel;
	private CodeBrowserPlugin cbPlugin;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.showTool();
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(ByteViewerPlugin.class.getName());

		plugin = env.getPlugin(ByteViewerPlugin.class);
		tool.showComponentProvider(plugin.getProvider(), true);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		program = buildNotepad();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		panel = plugin.getProvider().getByteViewerPanel();
	}

	private Program buildNotepad() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 1000);
		builder.createMemory("mem1", "0xf0001300", 1000);

		// give us distinguishable bytes
		builder.setBytes("0x1001000", "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff");

		// ascii - "message"
		builder.setBytes("0x1001100", "6d 65 73 73 61 67 65 00");
		builder.applyDataType("0x1001100", new StringDataType());

		return builder.getProgram();
	}

	private Program build8051() throws Exception {
		ProgramBuilder notepadBuilder = new ProgramBuilder("seg", ProgramBuilder._X86_16_REAL_MODE);
		notepadBuilder.createMemory("mem1", "0000:0000", 0x8000);
		return notepadBuilder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testOpenProgram() {
		assertEquals("Hex", panel.getCurrentComponent().getDataModel().getName());
		DockingActionIf action = getAction(plugin, "Byte Viewer Options");
		assertTrue(action.isEnabled());
		assertEquals(1, panel.getNumberOfViews());
	}

	@Test
	public void testOpenProgramNoMemory() throws Exception {
		tool.removePlugins(new Plugin[] { cbPlugin });

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

		program = buildNotepad();
		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
		});
		waitForSwing();

		// no errors should occur
	}

	@Test
	public void testAddRemoveViews() throws Exception {
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Ascii", true);
		setViewSelected(dialog, "Octal", true);
		pressButtonByText(dialog.getComponent(), "OK");

		assertEquals(3, panel.getNumberOfViews());

		DataModelInfo info = panel.getDataModelInfo();
		String[] names = info.getNames();
		assertEquals(3, names.length);
		Set<String> viewNames = new HashSet<>(Arrays.asList(names));
		assertTrue(viewNames.contains("Hex"));
		assertTrue(viewNames.contains("Octal"));
		assertTrue(viewNames.contains("Ascii"));

		// verify cursor position is the same across all views
		// verify the view is visible
		ByteViewerComponent bc = findComponent(panel, "Hex");
		assertTrue(bc.isVisible());
		ByteBlockInfo bbInfo = bc.getViewerCursorLocation();

		bc = findComponent(panel, "Ascii");
		assertTrue(bc.isVisible());
		assertEquals(bbInfo, bc.getViewerCursorLocation());

		bc = findComponent(panel, "Octal");
		assertTrue(bc.isVisible());
		assertEquals(bbInfo, bc.getViewerCursorLocation());

		dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Ascii", false);
		setViewSelected(dialog, "Hex", false);
		pressButtonByText(dialog.getComponent(), "OK");

		assertEquals(1, panel.getNumberOfViews());

		info = panel.getDataModelInfo();
		names = info.getNames();
		assertEquals(1, names.length);
		assertEquals("Octal", names[0]);

	}

	@Test
	public void testSetSelection() throws Exception {
		loadViews("Ascii", "Octal");

		final FieldSelection fsel = new FieldSelection();
		fsel.addRange(0, 0, 8, 7);

		ByteViewerComponent ascii = getView("Ascii");
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
			((ProgramByteBlockSet) plugin.getProvider().getByteBlockSet()).getAddressSet(bsel);

		// subtract one address from code browser selection since it is on
		// a code unit boundary
		psel = new ProgramSelection(psel.subtract(new AddressSet(addr(0x01001087))));
		assertTrue(psel.hasSameAddresses(set));
	}

	@Test
	public void testSetSelectionWithMouse() throws Exception {

		loadViews("Ascii", "Octal");

		ByteViewerComponent c = panel.getCurrentComponent();
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(addr(0x01001004));

		Point startPoint = c.getCursorPoint();

		goToByte("0x010010bc");
		Point endPoint = c.getCursorPoint();

		dragMouse(c, 1, startPoint.x, startPoint.y, endPoint.x, endPoint.y, 0);
		waitForSwing();

		ByteBlockSelection sel = c.getViewerSelection();
		ByteViewerComponent octal = findComponent(panel, "Octal");
		assertTrue(byteBlockSelectionEquals(sel, octal.getViewerSelection()));

		ProgramSelection psel = cbPlugin.getCurrentSelection();
		ByteBlockSelection bsel = panel.getViewerSelection();

		// convert bsel to an address set
		AddressSet set =
			((ProgramByteBlockSet) plugin.getProvider().getByteBlockSet()).getAddressSet(bsel);
		assertTrue(psel.hasSameAddresses(set));
	}

	@Test
	public void testProcessSelectionEvent() throws Exception {
		loadViews("Ascii", "Octal");

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
		c = findComponent(panel, "Ascii");
		assertTrue(byteBlockSelectionEquals(bsel, c.getViewerSelection()));

		ProgramSelection psel = cbPlugin.getCurrentSelection();

		bsel = panel.getViewerSelection();

		// convert bsel to an address set
		set = ((ProgramByteBlockSet) plugin.getProvider().getByteBlockSet()).getAddressSet(bsel);
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
		loadViews("Ascii", "Octal");
		// verify that the selections are the same after adding views
		ByteViewerComponent octalC = findComponent(panel, "Octal");
		assertTrue(byteBlockSelectionEquals(sel, octalC.getViewerSelection()));

		ByteViewerComponent asciiC = findComponent(panel, "Ascii");
		assertTrue(byteBlockSelectionEquals(sel, asciiC.getViewerSelection()));

	}

	@Test
	public void testMultiRangeSelection() throws Exception {
		loadViews("Ascii", "Octal");

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

		ByteViewerComponent asciiC = findComponent(panel, "Ascii");
		assertTrue(byteBlockSelectionEquals(sel, asciiC.getViewerSelection()));

	}

	@Test
	public void testLocationChanges() throws Exception {
		loadViews("Ascii", "Octal");

		ByteViewerComponent c = panel.getCurrentComponent();

		goToByte("0x01001004");

		ByteBlockInfo info = c.getViewerCursorLocation();
		ByteViewerComponent ascii = getView("Ascii");
		assertEquals(info, ascii.getViewerCursorLocation());
		ByteViewerComponent octal = getView("Octal");
		assertEquals(info, octal.getViewerCursorLocation());

		// convert to address
		Address addr = convertToAddr(info);
		assertEquals(addr(0x01001004), addr);

		assertEquals(addr, cbPlugin.getCurrentAddress());

		goToByte("0x01001081");

		info = c.getViewerCursorLocation();
		assertEquals(info, ascii.getViewerCursorLocation());
		assertEquals(info, octal.getViewerCursorLocation());

		// convert to addr
		addr = convertToAddr(info);
		assertEquals(addr(0x01001081), addr);
		// code browser will be on a code unit boundary
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
		assertEquals(cu.getMinAddress(), cbPlugin.getCurrentAddress());

		goToByte("0xf0001300");

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

		goToByte("0x01001004");
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

		goToByte("0x01001004");
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

		goToByte("0x01001005");
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
		FixedBitSizeValueField field =
			(FixedBitSizeValueField) getInstanceField("bytesPerLineField", d);
		runSwing(() -> field.setValue(BigInteger.valueOf(10)));
		pressButtonByText(d.getComponent(), "OK");

		waitForSwing();

		// verify that the bytes per line is 10
		assertEquals(10, plugin.getProvider().getBytesPerLine());
		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(10, c.getNumberOfFields());
		assertEquals(8, plugin.getProvider().getOffset());
	}

	@Test
	public void testSetAlignedAddress() throws Exception {

		goToByte("0x0100100b");

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		AddressInput ai = (AddressInput) getInstanceField("addressInputField", d);

		// verify that the text field has the min address since the
		// current offset is 0
		assertEquals(program.getMinAddress(), ai.getAddress());

		runSwing(() -> ai.setValue("0100100b"));
		pressButtonByText(d.getComponent(), "OK");
		// verify that offset label on the plugin shows '5'
		assertEquals(5, plugin.getProvider().getOffset());
		assertEquals("5", findLabelStr(plugin.getProvider().getComponent(), "Offset"));
		assertEquals("0100100b", findLabelStr(plugin.getProvider().getComponent(), "Insertion"));

		FieldLocation floc = getFieldLocation(addr(0x100101b));
		assertEquals(2, floc.getIndex().intValue());
		assertEquals(0, floc.getFieldNum());

		floc = getFieldLocation(addr(0x100102b));
		assertEquals(3, floc.getIndex().intValue());
		assertEquals(0, floc.getFieldNum());
	}

	@Test
	public void testSetBaseAddressSegmented() throws Exception {

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram();

		waitForSwing();

		program = build8051();
		pm.openProgram(program.getDomainFile());

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		AddressInput ai = (AddressInput) getInstanceField("addressInputField", d);

		// verify that the text field has the min address since the
		// current offset is 0
		assertEquals(program.getMinAddress(), ai.getAddress());

		runSwing(() -> ai.setValue("0000:0c06"));
		pressButtonByText(d.getComponent(), "OK");

		assertEquals(10, plugin.getProvider().getOffset());
	}

	@Test
	public void testSetGroupSize() throws Exception {

		ByteViewerComponent c = panel.getCurrentComponent();
		panel.setCurrentView(c); // force component to have focus

		goToByte("0x0100100b");

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		FixedBitSizeValueField field =
			(FixedBitSizeValueField) getInstanceField("groupSizeField", dialog);

		// verify that the text field has the min address since the
		// current offset is 0

		runSwing(() -> field.setValue(BigInteger.valueOf(2)));
		pressButtonByText(dialog.getComponent(), "OK");

		assertEquals(2, c.getDataModel().getGroupSize());
	}

	@Test
	public void testReorderViews() throws Exception {
		loadViews("Ascii", "Octal");
		final ByteViewerHeader columnHeader =
			(ByteViewerHeader) findContainer(panel, ByteViewerHeader.class);
		// move column 3 to 2
		runSwing(() -> {
			TableColumnModelEvent ev =
				new TableColumnModelEvent(columnHeader.getColumnModel(), 3, 2);
			panel.columnMoved(ev);
		});

		String[] names = panel.getDataModelInfo().getNames();

		// move column 1 to 0
		runSwing(() -> {
			TableColumnModelEvent ev =
				new TableColumnModelEvent(columnHeader.getColumnModel(), 2, 1);
			panel.columnMoved(ev);
		});
		String[] newNames = panel.getDataModelInfo().getNames();
		assertEquals(names[0], newNames[1]);
		assertEquals(names[1], newNames[0]);
		assertEquals(names[2], newNames[2]);

	}

	@Test
	public void testReorderViewsSaveState() throws Exception {

		loadViews("Ascii", "Octal");
		final ByteViewerHeader columnHeader =
			(ByteViewerHeader) findContainer(panel, ByteViewerHeader.class);
		// move column 3 to 2
		runSwing(() -> {
			TableColumnModelEvent ev =
				new TableColumnModelEvent(columnHeader.getColumnModel(), 3, 2);
			panel.columnMoved(ev);
		});

		// move column 1 to 0
		runSwing(() -> {
			TableColumnModelEvent ev =
				new TableColumnModelEvent(columnHeader.getColumnModel(), 1, 0);
			panel.columnMoved(ev);
		});
		String[] names = panel.getDataModelInfo().getNames();

		env.saveRestoreToolState();
		String[] newNames = panel.getDataModelInfo().getNames();
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], newNames[i]);
		}
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

//==================================================================================================
// Private Methods
//==================================================================================================	

	@SuppressWarnings("unchecked")
	private void assertOnlyOneProviderToolbarAction() {

		DockingWindowManager dwm = tool.getWindowManager();
		ActionToGuiMapper guiActions =
			(ActionToGuiMapper) getInstanceField("actionToGuiMapper", dwm);
		GlobalMenuAndToolBarManager menuManager =
			(GlobalMenuAndToolBarManager) getInstanceField("menuAndToolBarManager", guiActions);

		Map<WindowNode, WindowActionManager> windowToActionManagerMap =
			(Map<WindowNode, WindowActionManager>) getInstanceField("windowToActionManagerMap",
				menuManager);

		ProgramByteViewerComponentProvider provider = plugin.getProvider();
		DockingActionIf showAction =
			(DockingActionIf) getInstanceField("showProviderAction", provider);
		String actionName = showAction.getName();
		List<DockingActionIf> matches = new ArrayList<>();
		for (WindowActionManager actionManager : windowToActionManagerMap.values()) {

			ToolBarManager toolbarManager =
				(ToolBarManager) getInstanceField("toolBarMgr", actionManager);
			Map<String, List<ToolBarItemManager>> groupToItems =
				(Map<String, List<ToolBarItemManager>>) getInstanceField("groupToItemsMap",
					toolbarManager);

			Collection<List<ToolBarItemManager>> values = groupToItems.values();
			for (List<ToolBarItemManager> list : values) {
				for (ToolBarItemManager manager : list) {
					DockingActionIf action = manager.getAction();
					if (actionName.equals(action.getName())) {
						matches.add(action);
					}
				}
			}
		}

		assertEquals("Should only have 1 action on toolbar to show the provider", 1,
			matches.size());
	}

	private void goToOperand(String addr) {
		goTo(addr(addr), OperandFieldFactory.FIELD_NAME);
	}

	private void goTo(Address a, String fieldName) {
		int row = 0;
		int col = 0;
		assertTrue(cbPlugin.goToField(a, fieldName, row, col));
	}

	private void leftArrow() {
		runSwing(() -> {
			ByteViewerComponent view = panel.getCurrentComponent();
			view.cursorLeft();
		});
	}

	private void rightArrow() {

		runSwing(() -> {
			ByteViewerComponent view = panel.getCurrentComponent();
			view.cursorRight();
		});
	}

	private void rightArrowListing() {
		FieldPanel fp = cbPlugin.getFieldPanel();
		runSwing(() -> fp.cursorRight());
	}

	private void leftArrowListing() {
		FieldPanel fp = cbPlugin.getFieldPanel();
		runSwing(() -> fp.cursorLeft());
	}

	private void assertListingPosition(String expectedFieldText, int expectedColumn) {
		FieldPanel fp = cbPlugin.getFieldPanel();

		String fieldText = runSwing(() -> {
			Field field = fp.getCurrentField();
			String text = field.getText();
			return text;
		});
		assertEquals(expectedFieldText, fieldText);

		FieldLocation location = runSwing(() -> fp.getCursorLocation());
		assertEquals(expectedColumn, location.getCol());
	}

	private void assertPosition(ByteViewerComponent view, String expectedFieldText,
			int expectedColumn) {

		String fieldText = runSwing(() -> {
			Field field = view.getCurrentField();
			String text = field.getText();
			return text;
		});
		assertEquals(expectedFieldText, fieldText);

		FieldLocation location = runSwing(() -> view.getCursorLocation());
		assertEquals(expectedColumn, location.getCol());
	}

	private void goToByte(String addr) {
		goToByte(addr(addr));
	}

	private void goToByte(Address addr) {

		ByteViewerComponent view = runSwing(() -> panel.getCurrentComponent());
		goToByte(view, addr);
	}

	private void goToByte(ByteViewerComponent view, Address addr) {
		FieldLocation loc = getFieldLocation(addr);
		runSwing(() -> {
			view.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});
	}

	private void setViewSelected(ByteViewerOptionsDialog dialog, String viewName,
			boolean selected) {
		Map<?, ?> checkboxMap = (Map<?, ?>) getInstanceField("checkboxMap", dialog);
		JCheckBox checkbox = (JCheckBox) checkboxMap.get(viewName);
		checkbox.setSelected(selected);
	}

	private ByteViewerOptionsDialog launchByteViewerOptions() {
		final DockingActionIf action = getAction(plugin, "Byte Viewer Options");
		assertTrue(action.isEnabled());

		runSwing(() -> action.actionPerformed(new ActionContext()), false);
		waitForSwing();
		ByteViewerOptionsDialog d = waitForDialogComponent(ByteViewerOptionsDialog.class);
		return d;
	}

	private void setView(ByteViewerComponent view) {
		runSwing(() -> panel.setCurrentView(view));
	}

	private ByteViewerComponent getView(String name) {
		List<ByteViewerComponent> views = runSwing(() -> panel.getViewList());
		for (ByteViewerComponent viewer : views) {
			if (viewer.getName().equals(name)) {
				return viewer;
			}
		}

		fail("Cannot find view '" + name + "'");
		return null;
	}

	private FieldLocation getFieldLocation(Address addr) {

		return runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			ProgramByteBlockSet blockset =
				(ProgramByteBlockSet) plugin.getProvider().getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
			return c.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
		});
	}

	private Address addr(long offset) {
		return addr(Long.toHexString(offset));
	}

	private Address addr(String offset) {
		return program.getAddressFactory().getAddress(offset);
	}

	private Address convertToAddr(ByteBlockInfo info) {
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
			if (!range1.equals(range2)) {
				return false;
			}
		}
		return true;
	}

	private ByteViewerComponent findComponent(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof ByteViewerComponent) {
				if (((ByteViewerComponent) element).getDataModel().getName().equals(name)) {
					return (ByteViewerComponent) element;
				}
			}
			else if (element instanceof Container) {
				ByteViewerComponent bvc = findComponent((Container) element, name);
				if (bvc != null) {
					return bvc;
				}
			}
		}
		return null;
	}

	private void loadViews(String... viewNames) {
		assertNotEquals(0, viewNames.length);
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		for (String name : viewNames) {
			setViewSelected(dialog, name, true);
		}
		pressButtonByText(dialog.getComponent(), "OK");
	}

	private Container findContainer(Container parent, Class<?> theClass) {
		Component[] c = parent.getComponents();
		for (Component element : c) {
			if (element.getClass() == theClass) {
				return (Container) element;
			}
			if (element instanceof Container) {
				Container container = findContainer((Container) element, theClass);
				if (container != null) {
					return container;
				}
			}
		}
		return null;
	}

	private String findLabelStr(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof JLabel) {
				if (name.equals(((JLabel) element).getName())) {
					return ((JLabel) element).getText();
				}
			}
			if (element instanceof Container) {
				String str = findLabelStr((Container) element, name);
				if (str != null) {
					return str;
				}
			}
		}
		return null;
	}

}
