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

import java.awt.Cursor;
import java.util.List;

import org.junit.*;

import docking.ActionContext;
import ghidra.GhidraOptions;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.format.actions.InsertRowAction;
import ghidra.app.util.viewer.format.actions.RemoveRowAction;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class HeaderTest extends AbstractGhidraHeadedIntegrationTest {
	private static final int BUTTON_ONE = 1;
	private static final int NO_MODIFIERS = 0;
	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private CodeBrowserPlugin cb;
	private FieldHeader header;
	private int rowHeight;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setUpCodeBrowserTool(tool);

		program = buildProgram();
		env.showTool(program);

		runSwing(() -> cb.getListingPanel().showHeader(true));
		header = cb.getListingPanel().getFieldHeader();
		rowHeight = getRowHeight();

		initializeOptions();

		cb.goToField(addr("0x1003522"), "Address", 0, 0);
	}

	private void initializeOptions() {
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		String optionsName = "Address Field" + Options.DELIMITER + "Address Display Options";
		AddressFieldOptionsWrappedOption afowo =
			(AddressFieldOptionsWrappedOption) options.getCustomOption(optionsName, null);
		afowo.setRightJustify(false);
		options.setCustomOption(optionsName, afowo);

	}

	private int getRowHeight() {
		@SuppressWarnings("unchecked")
		List<FieldHeaderComp> list =
			(List<FieldHeaderComp>) getInstanceField("fieldHeaderComps", header);
		FieldHeaderComp fieldHeaderComp = list.get(0);
		return (int) getInstanceField("rowHeight", fieldHeaderComp);
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
		return builder.getProgram();
	}

	private void setUpCodeBrowserTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testNameMapper() {
		FormatManager formatManager = header.getFormatManager();
		FieldFactory[] factories = (FieldFactory[]) getInstanceField("factorys", formatManager);
		FieldFactory factory = FieldFactoryNameMapper.getFactoryPrototype("Mnemonic", factories);
		assertNotNull(factory);
		assertEquals("Mnemonic", factory.getFieldName());
	}

	@Test
	public void testMakeFieldWider() {
		ListingField bf = cb.getCurrentField();
		int fieldStart = bf.getStartX();
		int distance = 10;
		int row = 3;
		dragFieldEdge(fieldStart, row, distance);

		waitForSwing();
		bf = cb.getCurrentField();
		assertEquals(fieldStart + distance, bf.getStartX());
	}

	private void dragFieldEdge(int fieldStartX, int row, int delta) {
		dragMouse(header.getHeaderTab(), BUTTON_ONE, fieldStartX, row(3), fieldStartX + delta,
			row(3), NO_MODIFIERS);
	}

	private int row(int i) {
		return i * rowHeight + (rowHeight / 2);
	}

	@Test
	public void testMakeFieldSmaller() {
		ListingField bf = cb.getCurrentField();
		int startX = bf.getStartX();
		int width = bf.getWidth();
		int endX = startX + width;
		int row = 3;
		int distance = -10;
		dragFieldEdge(endX, row, distance);
		waitForSwing();
		bf = cb.getCurrentField();
		assertEquals(width + distance, bf.getWidth());

	}

	@Test
	public void testDragRight() {
		ListingField bf = cb.getCurrentField();
		// this is the second field on row 3, drag the first field past the middle of this field
		// which causes this field to move to the left edge

		int startX = bf.getStartX();
		int width = bf.getWidth();
		int middleFirstFieldX = startX / 2;
		int pastMiddleSecondFieldX = startX + width / 2 + 1;
		int row = 3;
		dragField(row, middleFirstFieldX, row, pastMiddleSecondFieldX);

		waitForSwing();
		bf = cb.getCurrentField();
		assertEquals(0, bf.getStartX());
	}

	private void dragField(int dragRow, int dragFieldX, int dropRow, int dropFieldX) {
		int dragY = row(dragRow);
		int dropY = row(dropRow);
		dragMouse(header.getHeaderTab(), BUTTON_ONE, dragFieldX, dragY, dropFieldX, dropY,
			NO_MODIFIERS);
	}

	@Test
	public void testCursorNearEdge() {
		Cursor cursor = header.getHeaderTab().getCursor();
		assertEquals("Default Cursor", cursor.getName());

		ListingField bf = cb.getCurrentField();
		int startX = bf.getStartX();
		int endX = startX + bf.getWidth();

		// move the cursor just before the end of the first column, startX has the position
		// of the start of the second column field.
		moveMouse(header.getHeaderTab(), startX - 1, row(3));

		waitForSwing();

		cursor = header.getHeaderTab().getCursor();
		assertEquals("East Resize Cursor", cursor.getName());

		// move the cursor to the middle of the second col
		moveMouse(header.getHeaderTab(), (startX + endX) / 2, row(3));

		waitForSwing();

		cursor = header.getHeaderTab().getCursor();
		assertEquals("Default Cursor", cursor.getName());

		// move the cursor to near the beginning of the second field
		moveMouse(header.getHeaderTab(), startX + 1, row(3));

		waitForSwing();

		cursor = header.getHeaderTab().getCursor();
		assertEquals("East Resize Cursor", cursor.getName());
	}

	@Test
	public void testDragToNewLine() {
		ListingField bf = cb.getCurrentField();
		int startX = bf.getStartX();
		int width = bf.getWidth();
		int dragX = startX + width / 2;
		int dropX = 200; // any x location
		int dragRow = 3;
		int dropRow = 8;
		dragField(dragRow, dragX, dropRow, dropX);
		waitForSwing();
		cb.goToField(addr("0x1003522"), "Address", 0, 0);
		waitForSwing();
		bf = cb.getCurrentField();
		assertEquals(0, bf.getStartX());
	}

	@Test
	public void testDragToPastBottomRow() {
		FieldFormatModel model = header.getFormatManager().getCodeUnitFormat();
		assertEquals(7, model.getNumRows());
		ListingField bf = cb.getCurrentField();
		int startX = bf.getStartX();
		int width = bf.getWidth();
		int dragX = startX + width / 2;
		int dropX = 200; // any x location
		int dragRow = 3;
		int dropRow = 7;
		dragField(dragRow, dragX, dropRow, dropX);

		waitForSwing();
		cb.goToField(addr("0x1003522"), "Address", 0, 0);
		waitForSwing();
		bf = cb.getCurrentField();
		assertEquals(0, bf.getStartX());
		assertEquals(8, model.getNumRows());

		// now drag it back up
		dragField(7, width / 2, 0, 0);
		assertEquals(7, model.getNumRows());
	}

	@Test
	public void testDraggingLeftPastAnotherField() {
		ListingField bf = cb.getCurrentField();
		int startX = bf.getStartX();
		int width = bf.getWidth();
		int dragX = startX + width / 2;
		int row = 3;
		int dropX = 0;
		dragField(row, dragX, row, dropX);
		bf = cb.getCurrentField();
		assertEquals(0, bf.getStartX());
	}

	@Test
	public void testInsertDeleteRow() {
		FieldFormatModel model = header.getHeaderTab().getModel();
		InsertRowAction act = new InsertRowAction("Test", header);
		act.isEnabledForContext(new ActionContext(cb.getProvider()).setContextObject(
			new FieldHeaderLocation(model, null, 0, 0)));
		performAction(act, true);
		assertEquals(8, model.getNumRows());
		assertEquals(0, model.getNumFactorys(0));
		RemoveRowAction act2 = new RemoveRowAction("Test", header);
		act2.isEnabledForContext(new ActionContext(cb.getProvider()).setContextObject(
			new FieldHeaderLocation(model, null, 0, 0)));
		performAction(act2, true);
		assertEquals(7, model.getNumRows());
		assertEquals(2, model.getNumFactorys(0));
	}

	@Test
	public void testDragToNewInsertedLine() {
		FieldFormatModel model = header.getHeaderTab().getModel();
		ListingField bf = cb.getCurrentField();
		int startX = bf.getStartX();
		InsertRowAction act = new InsertRowAction("Test", header);
		act.isEnabledForContext(new ActionContext(cb.getProvider()).setContextObject(
			new FieldHeaderLocation(model, null, 0, 0)));
		performAction(act, true);
		int width = bf.getWidth();
		int dragX = startX + width / 2;
		int dragRow = 4;
		int dropX = 200; // any x will do
		int dropRow = 0;
		dragField(dragRow, dragX, dropRow, dropX);
		waitForSwing();
		cb.goToField(addr("0x1003522"), "Address", 0, 0);
		waitForSwing();
		bf = cb.getCurrentField();
		assertEquals(0, bf.getStartX());
	}

	@Test
	public void testDisableField() {
		cb.goToField(addr("0x1003522"), "Address", 0, 0);
		assertTrue(cb.getCurrentFieldText().equals("01003522"));

		ListingField bf = cb.getCurrentField();
		FieldFormatModel model = header.getHeaderTab().getModel();
		bf.getFieldFactory().setEnabled(false);
		model.modelChanged();

		cb.goToField(addr("0x1003522"), "Bytes", 0, 0);
		cb.goToField(addr("0x1003522"), "Address", 0, 0);
		cb.goToField(addr("0x1003522"), "Address", 0, 0);
		assertTrue(!cb.getCurrentFieldText().equals("1003522"));
		bf.getFieldFactory().setEnabled(true);
		model.modelChanged();
		cb.goToField(addr("0x1003522"), "Address", 0, 0);
		cb.updateNow();
		assertEquals("01003522", cb.getCurrentFieldText());
	}

	@Test
	public void testHeaderSwitching() {
		cb.goToField(addr("0x1003522"), "Address", 0, 0);
		FieldFormatModel model = header.getHeaderTab().getModel();
		assertEquals("Instruction/Data", model.getName());

		cb.goToField(addr("0xf0001300"), "Separator", 0, 0);
		model = header.getHeaderTab().getModel();
		assertEquals("Address Break", model.getName());

		StructureDataType struct = new StructureDataType("fred", 7);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), struct);
		tool.execute(cmd, program);
		cb.goToField(addr("0x1007000"), "+", 0, 0);

		click(cb, 1);
		waitForSwing();

		cb.goToField(addr("0x1007001"), "+", 0, 0);
		model = header.getHeaderTab().getModel();
		assertEquals("Open Data", model.getName());

		cb.goToField(addr("0x1007000"), "+", 0, 0);
		model = header.getHeaderTab().getModel();
		assertEquals("Instruction/Data", model.getName());
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

}
