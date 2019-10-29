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
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.*;

import java.awt.Dimension;
import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.data.CreateStructureCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FieldHeader;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.test.AbstractProgramBasedTest;

public class CodeBrowserScreenMovementTest extends AbstractProgramBasedTest {

	private static final String NESTED_STRUCT_ADDR = "0x1007000";

	private AddressFactory addrFactory;
	private FieldPanel fp;

	@Before
	public void setUp() throws Exception {

		// warning: this test is sensitive to size and layout of the visible component providers;
		//          any layout changes may affect the values being tested below

		initialize();

		fp = codeBrowser.getFieldPanel();

		adjustFieldPanelSize(19);
		resetFormatOptions(codeBrowser);
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		builder.createMemory(".bound_import.table", "0xf0000428", 0xa8);
		builder.createMemory(".debug_data", "0xf0001300", 0x1c);
		builder.applyDataType("f000130d", new DoubleDataType(), 1);
		builder.applyDataType("1001000", new Pointer32DataType(), 7);
		builder.disassemble("0x10036a2", 1);

		// for structure in structure test
		builder.createMemoryReference("1001012", NESTED_STRUCT_ADDR, RefType.DATA,
			SourceType.DEFAULT, 0);
		builder.createMemoryReference("1001013", "10070001", RefType.DATA, SourceType.DEFAULT, 0);
		builder.createMemoryReference("1001014", "10070002", RefType.DATA, SourceType.DEFAULT, 0);

		return builder.getProgram();
	}

	@Override
	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testOpenClose() throws Exception {

		assertNotNull(codeBrowser.getCurrentLocation());
		assertEquals(addr("0x1001000"), codeBrowser.getCurrentAddress());

		assertEquals(program.getMemory(), codeBrowser.getView());

		closeProgram();
		assertNull(codeBrowser.getCurrentLocation());
	}

	@Test
	public void testBasicControls() throws Exception {

		// warning: this test is sensitive to size and layout of the visible component providers;
		//          any layout changes may affect the values being tested below

		fp = codeBrowser.getFieldPanel();
		ListingPanel panel = codeBrowser.getListingPanel();
		JScrollBar scrollbar = panel.getVerticalScrollBar();

		bottomOfFile(fp);
		Address max = program.getMemory().getMaxAddress();
		assertEquals(max, codeBrowser.getCurrentAddress());

		topOfFile(fp);
		assertEquals(program.getMemory().getMinAddress(), codeBrowser.getCurrentAddress());

		bottomOfFile(fp);
		setScrollbarValue(scrollbar, 0);

		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

		setScrollbarValue(scrollbar, scrollbar.getMaximum());
		assertEquals(addr("0xf0001304"), codeBrowser.getAddressTopOfScreen());

		topOfFile(fp);
		cursorUp(fp);
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

		for (int i = 0; i < 26; i++) {
			cursorDown(fp);
		}
		assertEquals(addr("0x1001010"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x100102b"), codeBrowser.getCurrentAddress());

		for (int i = 0; i < 22; i++) {
			cursorUp(fp);
		}
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x1001000"), codeBrowser.getCurrentAddress());

		bottomOfFile(fp);

		for (int i = 0; i < 19; i++) {
			cursorUp(fp);
		}
		assertEquals(addr("0xf0001303"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0xf0001303"), codeBrowser.getCurrentAddress());

		for (int i = 0; i < 19; i++) {
			cursorDown(fp);
		}
		assertEquals(addr("0xf0001304"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0xf000131b"), codeBrowser.getCurrentAddress());

	}

	@Test
	public void testPgUpPgDn() throws Exception {

		pageDown(fp);
		assertEquals(addr("0x1001023"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x1001023"), codeBrowser.getCurrentAddress());
		cursorDown(fp);
		cursorDown(fp);
		cursorDown(fp);
		pageUp(fp);
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x1001000"), codeBrowser.getCurrentAddress());

		for (int i = 0; i < 100; i++) {
			cursorDown(fp);
		}
		for (int i = 0; i < 10; i++) {
			pageUp(fp);
		}
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

		bottomOfFile(fp);
		pageUp(fp);
		cursorDown(fp);
		cursorDown(fp);
		pageDown(fp);

		assertEquals(addr("0xf0001304"), codeBrowser.getAddressTopOfScreen());

	}

	@Test
	public void testScroll() throws Exception {

		ListingPanel panel = codeBrowser.getListingPanel();
		JScrollBar scrollbar = panel.getVerticalScrollBar();

		for (int i = 0; i < 22; i++) {
			scrollbar.getUnitIncrement(1);
		}
		waitForPostedSwingRunnables();
		assertEquals(addr("0x1001027"), codeBrowser.getAddressTopOfScreen());

		for (int i = 0; i < 18; i++) {
			scrollbar.getUnitIncrement(-1);
		}
		waitForPostedSwingRunnables();
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

		for (int i = 0; i < 16; i++) {
			scrollbar.getBlockIncrement(1);
		}
		waitForPostedSwingRunnables();
		assertEquals(addr("0x1001136"), codeBrowser.getAddressTopOfScreen());

		for (int i = 0; i < 16; i++) {
			scrollbar.getBlockIncrement(-1);
		}
		waitForPostedSwingRunnables();
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

	}

	@Test
	public void testBasicControlsSmallView() throws Exception {

		ListingPanel panel = codeBrowser.getListingPanel();

		JScrollBar scrollbar = panel.getVerticalScrollBar();
		setView(new AddressSet(addr("0x1001000"), addr("0x10012ff")));
		assertEquals(768, fp.getLayoutModel().getNumIndexes().intValue());

		bottomOfFile(fp);
		assertEquals(addr("0x10012ff"), codeBrowser.getCurrentAddress());

		topOfFile(fp);
		assertEquals(addr("0x1001000"), codeBrowser.getCurrentAddress());

		bottomOfFile(fp);
		setScrollbarValue(scrollbar, 0);

		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

		setScrollbarValue(scrollbar, scrollbar.getMaximum());
		assertEquals(addr("0x10012ed"), codeBrowser.getAddressTopOfScreen());

		topOfFile(fp);
		cursorUp(fp);
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

		for (int i = 0; i < 26; i++) {
			cursorDown(fp);
		}
		assertEquals(addr("0x1001010"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x100102b"), codeBrowser.getCurrentAddress());

		for (int i = 0; i < 22; i++) {
			cursorUp(fp);
		}
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x1001000"), codeBrowser.getCurrentAddress());

		bottomOfFile(fp);

		for (int i = 0; i < 20; i++) {
			cursorUp(fp);
		}
		assertEquals(addr("0x10012eb"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x10012eb"), codeBrowser.getCurrentAddress());

		for (int i = 0; i < 20; i++) {
			cursorDown(fp);
		}
		assertEquals(addr("0x10012ed"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x10012ff"), codeBrowser.getCurrentAddress());

	}

	@Test
	public void testPgUpPgDnSmallView() throws Exception {

		setView(new AddressSet(addr("0x1001000"), addr("0x10012ff")));

		pageDown(fp);
		assertEquals(addr("0x1001023"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x1001023"), codeBrowser.getCurrentAddress());
		cursorDown(fp);
		cursorDown(fp);
		cursorDown(fp);
		pageUp(fp);
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());
		assertEquals(addr("0x1001000"), codeBrowser.getCurrentAddress());

		for (int i = 0; i < 100; i++) {
			cursorDown(fp);
		}
		for (int i = 0; i < 10; i++) {
			pageUp(fp);
		}
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

		bottomOfFile(fp);
		pageUp(fp);
		cursorDown(fp);
		cursorDown(fp);
		pageDown(fp);

		assertEquals(addr("0x10012ed"), codeBrowser.getAddressTopOfScreen());

	}

	@Test
	public void testScrollSmallView() throws Exception {

		ListingPanel panel = codeBrowser.getListingPanel();
		setView(new AddressSet(addr("0x1001000"), addr("0x10012ff")));
		JScrollBar scrollbar = panel.getVerticalScrollBar();

		for (int i = 0; i < 20; i++) {
			scrollbar.getUnitIncrement(1);
		}
		waitForPostedSwingRunnables();
		assertEquals(addr("0x1001025"), codeBrowser.getAddressTopOfScreen());

		for (int i = 0; i < 16; i++) {
			scrollbar.getUnitIncrement(-1);
		}
		waitForPostedSwingRunnables();
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

		for (int i = 0; i < 16; i++) {
			scrollbar.getBlockIncrement(1);
		}
		waitForPostedSwingRunnables();
		assertEquals(addr("0x1001136"), codeBrowser.getAddressTopOfScreen());

		for (int i = 0; i < 16; i++) {
			scrollbar.getBlockIncrement(-1);
		}
		waitForPostedSwingRunnables();
		assertEquals(addr("0x1001000"), codeBrowser.getAddressTopOfScreen());

	}

	@Test
	public void testViewSeparator() throws Exception {

		AddressSet set = new AddressSet(addr("0x1008500"), addr("0x1008507"));
		set.addRange(addr("0x1008510"), addr("0x1008520"));

		setView(set);

		for (int i = 0; i < 8; i++) {
			cursorDown(fp);
		}

		assertEquals(addr("0x1008510"), codeBrowser.getCurrentAddress());
		assertTrue(codeBrowser.getCurrentLocation() instanceof DividerLocation);

	}

	@Test
	public void testConnectedBrowsers() throws Exception {

		PluginTool tool2 = showSecondTool();

		CodeBrowserPlugin cb2 = getPlugin(tool2, CodeBrowserPlugin.class);

		env.connectTools(tool, tool2);

		codeBrowser.goToField(addr("0x1006420"), "Address", 0, 0);
		assertEquals("01006420", cb2.getCurrentFieldText());

		for (int i = 0; i < 1000; i++) {
			cursorRight(fp);
			assertEquals("i = " + i, codeBrowser.getCurrentFieldText(), cb2.getCurrentFieldText());
			assertEquals("i = " + i, codeBrowser.getCurrentFieldLoction(),
				cb2.getCurrentFieldLoction());
		}
	}

	@Test
	public void testOpenCloseStruct() throws Exception {

		StructureDataType struct = new StructureDataType("fred", 7);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), struct);
		tool.execute(cmd, program);
		codeBrowser.goToField(addr("0x1007000"), "+", 0, 0);
		assertTrue(codeBrowser.getCurrentField() instanceof OpenCloseField);
		codeBrowser.goToField(addr("0x1007000"), "Address", 0, 0);
		for (int i = 0; i < 7; i++) {
			Address addr = addr("0x1007000").add(i);
			codeBrowser.goToField(addr, "Address", 0, 0);
			assertEquals("01007000", codeBrowser.getCurrentFieldText());
		}
		codeBrowser.goToField(addr("0x1007007"), "Address", 0, 0);
		assertEquals("01007007", codeBrowser.getCurrentFieldText());

		codeBrowser.goToField(addr("0x1007000"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();

		codeBrowser.goToField(addr("0x1007001"), "Address", 0, 0);
		assertEquals("01007001", codeBrowser.getCurrentFieldText());
		codeBrowser.goToField(addr("0x1007002"), "Address", 0, 0);
		assertEquals("01007002", codeBrowser.getCurrentFieldText());
		codeBrowser.goToField(addr("0x1007006"), "Address", 0, 0);
		assertEquals("01007006", codeBrowser.getCurrentFieldText());

		codeBrowser.goToField(addr("0x1007000"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();

		codeBrowser.goToField(addr("0x1007000"), "Address", 0, 0);
		for (int i = 0; i < 7; i++) {
			Address addr = addr("0x1007000").add(i);
			codeBrowser.goToField(addr, "Address", 0, 0);
			assertEquals("01007000", codeBrowser.getCurrentFieldText());
		}
		codeBrowser.goToField(addr("0x1007007"), "Address", 0, 0);
		assertEquals("01007007", codeBrowser.getCurrentFieldText());

	}

	@Test
	public void testOpenCloseArray() throws Exception {

		ArrayDataType array = new ArrayDataType(new WordDataType(), 12, 2);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), array);
		tool.execute(cmd, program);
		codeBrowser.goToField(addr("0x1007000"), "+", 0, 0);
		assertTrue(codeBrowser.getCurrentField() instanceof OpenCloseField);
		codeBrowser.goToField(addr("0x1007000"), "Address", 0, 0);
		codeBrowser.goToField(addr("0x1007008"), "Address", 0, 0);
		assertEquals("01007000", codeBrowser.getCurrentFieldText());

		codeBrowser.goToField(addr("0x1007000"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();
		codeBrowser.goToField(addr("0x1007008"), "Address", 0, 0);
		assertEquals("01007008", codeBrowser.getCurrentFieldText());
		codeBrowser.goToField(addr("0x1007010"), "Address", 0, 0);
		assertEquals("01007010", codeBrowser.getCurrentFieldText());

		codeBrowser.goToField(addr("0x1007000"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();
		codeBrowser.goToField(addr("0x1007000"), "Address", 0, 0);
		codeBrowser.goToField(addr("0x1007008"), "Address", 0, 0);
		assertEquals("01007000", codeBrowser.getCurrentFieldText());

	}

	@Test
	public void testNestedOpenClose() throws Exception {

		StructureDataType struct = new StructureDataType("fred", 7);
		ArrayDataType array = new ArrayDataType(struct, 5, 7);
		ArrayDataType array2 = new ArrayDataType(array, 4, 35);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), array2);

		tool.execute(cmd, program);

		codeBrowser.goToField(addr("0x1007000"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();
		codeBrowser.goToField(addr("0x1007023"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();
		codeBrowser.goToField(addr("0x100702a"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();
		waitForPostedSwingRunnables();

		codeBrowser.goToField(addr("0x100702b"), "Address", 0, 0);
		assertEquals("0100702b", codeBrowser.getCurrentFieldText());
		codeBrowser.goToField(addr("0x1007023"), "Address", 0, 0);
		assertEquals("01007023", codeBrowser.getCurrentFieldText());
	}

	@Test
	public void testConnectedOpenStructs() throws Exception {

		PluginTool tool2 = showSecondTool();

		CodeBrowserPlugin cb2 = getPlugin(tool2, CodeBrowserPlugin.class);

		env.connectTools(tool, tool2);

		codeBrowser.goToField(addr("0x1007000"), "Address", 0, 0);
		assertEquals("01007000", cb2.getCurrentFieldText());

		StructureDataType struct = new StructureDataType("fred", 7);
		ArrayDataType array = new ArrayDataType(struct, 5, 7);
		ArrayDataType array2 = new ArrayDataType(array, 4, 35);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), array2);

		tool.execute(cmd, program);

		// trigger opening of the structure, which a goto will do
		goTo(codeBrowser, addr("0x1007000"));
		goTo(codeBrowser, addr("0x1007023"));
		goTo(codeBrowser, addr("0x100702a"));

		// trigger opening of the structure, which a goto will do
		goTo(cb2, addr("0x1007000"));
		goTo(cb2, addr("0x1007023"));
		goTo(cb2, addr("0x100702a"));

		// go to the start of the structure so that we can arrow through it
		goTo(codeBrowser, addr("0x1007000"));

		for (int i = 0; i < 300; i++) {
			cursorRight(fp);

			if (!codeBrowser.getCurrentFieldText().equals(cb2.getCurrentFieldText())) {
				System.err.println("text not equal at cursor move: " + i);
			}
			assertEquals(codeBrowser.getCurrentFieldText(), cb2.getCurrentFieldText());

			if (!codeBrowser.getCurrentFieldLoction().equals(cb2.getCurrentFieldLoction())) {
				System.err.println("location no equal at cursor move: " + i);
			}
			assertEquals(codeBrowser.getCurrentFieldLoction(), cb2.getCurrentFieldLoction());
		}

	}

	@Test
	public void testConnectedOneOpenOneClosedStructs() throws Exception {

		PluginTool tool2 = showSecondTool();

		CodeBrowserPlugin cb2 = getPlugin(tool2, CodeBrowserPlugin.class);
		resetFormatOptions(cb2);
		env.connectTools(tool, tool2);

		codeBrowser.goToField(addr("0x1007000"), "Address", 0, 0);
		assertEquals("01007000", cb2.getCurrentFieldText());

		StructureDataType struct = new StructureDataType("fred", 7);
		ArrayDataType array = new ArrayDataType(struct, 5, 7);
		ArrayDataType array2 = new ArrayDataType(array, 4, 35);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), array2);

		tool.execute(cmd, program);

		codeBrowser.goToField(addr("0x1007000"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();
		codeBrowser.goToField(addr("0x1007023"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();
		codeBrowser.goToField(addr("0x100702a"), "+", 0, 0);
		click(codeBrowser, 1);
		waitForPostedSwingRunnables();

		// this should open the other structure
		codeBrowser.goToField(addr("0x1007023"), "Address", 0, 0);

		assertEquals("01007023", cb2.getCurrentFieldText());

	}

	@Test
	public void testConnectedStructesWithDataXRefFields() throws Exception {

		PluginTool tool2 = showSecondTool();

		CodeBrowserPlugin cb2 = getPlugin(tool2, CodeBrowserPlugin.class);
		resetFormatOptions(cb2);
		env.connectTools(tool, tool2);

		addDataXrefFieldsToListing(codeBrowser);
		addDataXrefFieldsToListing(cb2);

		goTo(codeBrowser, addr("0x1007000"));
		assertEquals("01007000", cb2.getCurrentFieldText());

		createStructureInStructure(NESTED_STRUCT_ADDR);

		goTo(codeBrowser, addr("0x1007000"));
		goTo(cb2, addr("0x1007000"));
		expandData();

		runSwing(() -> codeBrowser.goToField(addr(NESTED_STRUCT_ADDR), "XRef Header", 0, 2));
		for (int i = 0; i < 50; i++) {
			cursorRight(fp);
			assertEquals("Locations didn't track across tools", codeBrowser.getCurrentFieldText(),
				cb2.getCurrentFieldText());
			assertEquals("Locations didn't track across tools", codeBrowser.getCurrentLocation(),
				cb2.getCurrentLocation());
		}
	}

	@Test
	public void testGetCurrentFieldSelection() throws Exception {

		assertNull(codeBrowser.getCurrentFieldTextSelection());

		FieldSelection sel = new FieldSelection();
		codeBrowser.goToField(addr("0x10036a2"), OperandFieldFactory.FIELD_NAME, 0, 2);
		FieldLocation l1 = fp.getCursorLocation();
		codeBrowser.goToField(addr("0x10036a2"), OperandFieldFactory.FIELD_NAME, 0, 7);
		FieldLocation l2 = fp.getCursorLocation();
		sel.addRange(l1, l2);
		setFieldSelection(fp, sel);

		assertEquals(",#0x0", codeBrowser.getCurrentFieldTextSelection());

		// now make a real program selection and verify the text selection goes away
		ProgramSelection programSelection =
			new ProgramSelection(addrFactory, addr("0x1003600"), addr("0x10036f0"));
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent(testName.getMethodName(), programSelection, program));

		assertNull(codeBrowser.getCurrentFieldTextSelection());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void createStructureInStructure(String addr) {
		int id = program.startTransaction("Structure");

		Structure struct = new StructureDataType("ParentStructure", 0);
		Structure child = new StructureDataType("ChildStructure", 0);
		child.add(new ByteDataType());
		child.add(new ByteDataType());
		struct.add(child);

		CreateStructureCmd cmd = new CreateStructureCmd(struct, addr(addr));

		cmd.applyTo(program);
		program.endTransaction(id, true);
	}

	private void expandData() {
		DockingActionIf expand = getAction(codeBrowser, "Toggle Expand/Collapse Data");
		performAction(expand, codeBrowser.getProvider().getActionContext(null), true);
	}

	private void addDataXrefFieldsToListing(CodeBrowserPlugin plugin) {
		runSwing(() -> {
			plugin.getListingPanel().showHeader(true);

			FieldHeader header = plugin.getListingPanel().getFieldHeader();
			int index = header.indexOfTab("Open Data");
			header.setSelectedIndex(index);
			FieldFormatModel model = header.getHeaderTab().getModel();
			addField(model, "XRef Header", 6);
			addField(model, "XRef", 7);

			plugin.getListingPanel().showHeader(false);
		});
	}

	private void addField(FieldFormatModel model, String fieldName, int column) {
		FieldFactory[] allFactories = model.getAllFactories();
		for (FieldFactory fieldFactory : allFactories) {
			if (fieldFactory.getFieldName().equals(fieldName)) {
				model.addFactory(fieldFactory, 0, column);
			}
		}
	}

	private void setFieldSelection(FieldPanel fp, FieldSelection sel) {
		fp.setSelection(sel);
		Class<?>[] argClasses = new Class<?>[] { EventTrigger.class };
		Object[] args = new Object[] { EventTrigger.GUI_ACTION };
		invokeInstanceMethod("notifySelectionChanged", fp, argClasses, args);
	}

	private void setUpCodeBrowserTool(PluginTool tool) throws Exception {
		CodeBrowserPlugin cbp = getPlugin(tool, CodeBrowserPlugin.class);
		resetFormatOptions(cbp);
	}

	private void goTo(final CodeBrowserPlugin plugin, final Address address) {
		final AtomicBoolean result = new AtomicBoolean();
		runSwing(() -> {
			CodeViewerProvider provider = plugin.getProvider();
			ProgramLocation location = new ProgramLocation(program, address);
			result.set(provider.goTo(program, location));
		});

		assertTrue(result.get());
	}

	private void setView(final AddressSet addrSet) {
		runSwing(() -> codeBrowser.viewChanged(addrSet), true);

	}

	private void adjustFieldPanelSize(int numRows) {
		JViewport vp = (JViewport) fp.getParent().getParent();
		codeBrowser.updateNow();
		int rowSize = getRowSize(fp);
		final int desiredViewportHeight = rowSize * numRows;
		Dimension d = vp.getExtentSize();
		doAdjustSize(vp, d.width + 200, desiredViewportHeight);
		codeBrowser.updateNow();
		d = vp.getExtentSize();
		doAdjustSize(vp, d.width, desiredViewportHeight);//scroll bar might go away
		codeBrowser.updateNow();

	}

	private void doAdjustSize(final JViewport vp, final int width, final int height) {
		runSwing(() -> {
			Dimension vpSize = vp.getExtentSize();
			JFrame f = tool.getToolFrame();
			Dimension frameSize = f.getSize();
			frameSize.height += height - vpSize.height;
			frameSize.width += width - vpSize.width;
			f.setSize(frameSize);
			fp.invalidate();
			f.validate();
		});
	}

	private int getRowSize(FieldPanel fieldPanel) {
		int rowHeight = 0;
		LayoutModel layoutModel = fieldPanel.getLayoutModel();
		Layout layout = layoutModel.getLayout(BigInteger.ZERO);
		for (int i = 0; i < layout.getNumFields(); i++) {
			Field field = layout.getField(i);
			int numRows = field.getNumRows();
			int fieldRowHeight = field.getHeight() / numRows;
			rowHeight = Math.max(rowHeight, fieldRowHeight);
		}
		return rowHeight;
	}

	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram();
	}

	private void setScrollbarValue(JScrollBar bar, int value) {
		runSwing(() -> bar.setValue(value));
		codeBrowser.updateNow();
		waitForSwing();
	}

	private void pageDown(final FieldPanel fp1) {
		runSwing(() -> fp1.pageDown());
		codeBrowser.updateNow();
		waitForSwing();
	}

	private void pageUp(final FieldPanel fp1) {
		runSwing(() -> fp1.pageUp());
		codeBrowser.updateNow();
		waitForSwing();
	}

	private void cursorDown(final FieldPanel fp1) {
		runSwing(() -> fp1.cursorDown());
	}

	private void cursorUp(final FieldPanel fp1) {
		runSwing(() -> fp1.cursorUp());
	}

	private void cursorRight(final FieldPanel fp1) {
		runSwing(() -> fp1.cursorRight());
	}

	private void topOfFile(final FieldPanel fp1) {
		runSwing(() -> fp1.cursorTopOfFile());
		codeBrowser.updateNow();
		waitForSwing();
	}

	private void bottomOfFile(final FieldPanel fp1) {
		runSwing(() -> fp1.cursorBottomOfFile());
		codeBrowser.updateNow();
		waitForSwing();
	}

	private void resetFormatOptions(CodeBrowserPlugin plugin) {
		Options fieldOptions = plugin.getFormatManager().getFieldOptions();
		List<String> names = fieldOptions.getOptionNames();
		for (int i = 0; i < names.size(); i++) {
			String name = names.get(i);
			if (!name.startsWith("Format Code")) {
				continue;
			}
			if (name.indexOf("Show ") >= 0 || name.indexOf("Flag ") >= 0) {
				fieldOptions.setBoolean(name, false);
			}
			else if (name.indexOf("Lines") >= 0) {
				fieldOptions.setInt(name, 0);
			}
		}
		waitForPostedSwingRunnables();
		plugin.updateNow();
	}

	private PluginTool showSecondTool() throws Exception {

		PluginTool tool2 = env.launchAnotherDefaultTool();
		setUpCodeBrowserTool(tool2);
		ProgramManager pm = tool2.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		showTool(tool2);
		return tool2;
	}
}
