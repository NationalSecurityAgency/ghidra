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
package ghidra.app.plugin.core.searchmem;

import static org.junit.Assert.*;

import java.awt.Container;
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.Program;

/**
 * Tests for searching for decimal values in memory.
 */
public class MemSearchDecimal2Test extends AbstractMemSearchTest {

	public MemSearchDecimal2Test() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		selectRadioButton("Decimal");
	}

	@Override
	protected Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory(".data", Long.toHexString(0x1008000), 0x600);
		builder.createMemory(".rsrc", Long.toHexString(0x100A000), 0x5400);
		builder.createMemory(".bound_import_table", Long.toHexString(0xF0000248), 0xA8);
		builder.createMemory(".debug_data", Long.toHexString(0xF0001300), 0x1C);

		//create and disassemble a function
		builder.setBytes(
			"0x01002cf5",
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 8b f8 eb 02 " +
				"33 ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b f0 85 f6 " +
				"74 27 56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75 08 ff 15 " +
				"04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75 10 ff 75 " +
				"08 ff 15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14");
		builder.disassemble("0x01002cf5", 0x121, true);
		builder.createFunction("0x01002cf5");

		//create some data

		builder.setBytes("0x1001004", "85 4f dc 77");
		builder.applyDataType("0x1001004", new Pointer32DataType(), 1);
		builder.createEncodedString("0x01001708", "Notepad", StandardCharsets.UTF_16BE, true);
		builder.createEncodedString("0x01001740", "something else", StandardCharsets.UTF_16BE, true);
		builder.createEncodedString("0x010013cc", "notepad.exe", StandardCharsets.US_ASCII, false);

		//create some undefined data
		builder.setBytes("0x1001500", "4e 00 65 00 77 00");
		builder.setBytes("0x1003000", "55 00");
		builder.setBytes("0x1004100", "64 00 00 00");//100 dec
		builder.setBytes("0x1004120", "50 ff 75 08");//7.4027124e-34 float
		builder.setBytes("0x1004135", "64 00 00 00");//100 dec
		builder.setBytes("0x1004200", "50 ff 75 08 e8 8d 3c 00");//1.588386874245921e-307
		builder.setBytes("0x1004247", "50 ff 75 08");//7.4027124e-34 float
		builder.setBytes("0x1004270", "65 00 6e 00 64 00 69 00");//29555302058557541 qword

		return builder.getProgram();
	}

	@Test
	public void testDecimalOptionsShowing() throws Exception {
		// select the Decimal option; verify radio buttons for decimal types
		// are showing in the Decimal Options panel.
		JRadioButton rb = (JRadioButton) findAbstractButtonByText(pane, "Byte");
		assertNotNull(rb);
		JPanel p = findTitledJPanel(rb, "Format Options");
		assertNotNull(p);
		assertTrue(p.isVisible());

		assertTrue(!rb.isSelected());
		assertTrue(rb.isVisible());

		rb = (JRadioButton) findAbstractButtonByText(pane, "Word");
		assertNotNull(rb);
		assertTrue(rb.isSelected());
		assertTrue(rb.isVisible());

		rb = (JRadioButton) findAbstractButtonByText(pane, "DWord");
		assertNotNull(rb);
		assertTrue(!rb.isSelected());
		assertTrue(rb.isVisible());

		rb = (JRadioButton) findAbstractButtonByText(pane, "QWord");
		assertNotNull(rb);
		assertTrue(!rb.isSelected());
		assertTrue(rb.isVisible());

		rb = (JRadioButton) findAbstractButtonByText(pane, "Float");
		assertNotNull(rb);
		assertTrue(!rb.isSelected());
		assertTrue(rb.isVisible());

		rb = (JRadioButton) findAbstractButtonByText(pane, "Double");
		assertNotNull(rb);
		assertTrue(!rb.isSelected());
		assertTrue(rb.isVisible());
	}

	@Test
	public void testInvalidEntry() throws Exception {
		// enter non-numeric value
		setValueText("z");
		assertEquals("", valueField.getText());
		assertEquals("", hexLabel.getText());
	}

	@Test
	public void testValueTooLarge() throws Exception {
		// select "Byte" and enter 260; should not accept "0"
		selectRadioButton("Byte");

		myTypeText("260");
		assertEquals("26", valueField.getText());
		assertEquals(statusLabel.getText(), "Number must be in the range [-128,255]");
	}

	@Test
	public void testValueTooLarge2() throws Exception {
		// select "Word" and enter 2698990; should not accept "26989"
		selectRadioButton("Word");

		myTypeText("2698990");
		assertEquals(statusLabel.getText(), "Number must be in the range [-32768,65535]");
		assertEquals("26989", valueField.getText());
	}

	@Test
	public void testNegativeValueEntered() throws Exception {
		// enter a negative value; the hexLabel should show the correct
		// byte sequence

		setValueText("-1234");
		assertEquals("2e fb ", hexLabel.getText());

		selectRadioButton("Byte");
		assertEquals("", valueField.getText());
		assertEquals("", hexLabel.getText());
		setValueText("-55");
		assertEquals("c9 ", hexLabel.getText());

		selectRadioButton("DWord");
		assertEquals("c9 ff ff ff ", hexLabel.getText());

		selectRadioButton("QWord");
		assertEquals("c9 ff ff ff ff ff ff ff ", hexLabel.getText());

		selectRadioButton("Float");
		assertEquals("00 00 5c c2 ", hexLabel.getText());

		selectRadioButton("Double");
		assertEquals("00 00 00 00 00 80 4b c0 ", hexLabel.getText());
	}

	@Test
	public void testMulipleValuesEntered() throws Exception {
		// enter values separated by a space; values should be accepted
		selectRadioButton("Byte");
		setValueText("12 34 56 78");
		assertEquals("0c 22 38 4e ", hexLabel.getText());

		selectRadioButton("Word");
		assertEquals("0c 00 22 00 38 00 4e 00 ", hexLabel.getText());

		selectRadioButton("DWord");
		assertEquals("0c 00 00 00 22 00 00 00 38 00 00 00 4e 00 00 00 ", hexLabel.getText());

		selectRadioButton("QWord");
		assertEquals("0c 00 00 00 00 00 00 00 22 00 00 00 00 00 00 00 "
			+ "38 00 00 00 00 00 00 00 4e 00 00 00 00 00 00 00 ", hexLabel.getText());

		selectRadioButton("Float");
		assertEquals("00 00 40 41 00 00 08 42 00 00 60 42 00 00 9c 42 ", hexLabel.getText());

		selectRadioButton("Double");
		assertEquals("00 00 00 00 00 00 28 40 00 00 00 00 00 00 41 40 "
			+ "00 00 00 00 00 00 4c 40 00 00 00 00 00 80 53 40 ", hexLabel.getText());
	}

	@Test
	public void testByteOrder() throws Exception {
		setValueText("12 34 56 78");
		selectRadioButton("Byte");
		selectRadioButton("Big Endian");
		// should be unaffected			
		assertEquals("0c 22 38 4e ", hexLabel.getText());

		selectRadioButton("Word");
		assertEquals("00 0c 00 22 00 38 00 4e ", hexLabel.getText());

		selectRadioButton("DWord");
		assertEquals("00 00 00 0c 00 00 00 22 00 00 00 38 00 00 00 4e ", hexLabel.getText());

		selectRadioButton("QWord");
		assertEquals("00 00 00 00 00 00 00 0c 00 00 00 00 00 00 00 22 "
			+ "00 00 00 00 00 00 00 38 00 00 00 00 00 00 00 4e ", hexLabel.getText());

		selectRadioButton("Float");
		assertEquals("41 40 00 00 42 08 00 00 42 60 00 00 42 9c 00 00 ", hexLabel.getText());

		selectRadioButton("Double");
		assertEquals("40 28 00 00 00 00 00 00 40 41 00 00 00 00 00 00 "
			+ "40 4c 00 00 00 00 00 00 40 53 80 00 00 00 00 00 ", hexLabel.getText());
	}

	@Test
	public void testFloatDoubleFormat() throws Exception {
		selectRadioButton("Float");

		setValueText("12.345");
		assertEquals("12.345", valueField.getText());
		assertEquals("1f 85 45 41 ", hexLabel.getText());

		selectRadioButton("Double");
		assertEquals("71 3d 0a d7 a3 b0 28 40 ", hexLabel.getText());
	}

	@Test
	public void testSearchByte() throws Exception {
		goTo(program.getMinAddress());

		List<Address> addrs = addrs(0x1002d3e, 0x1002d5b, 0x1004123, 0x1004203, 0x100424a);

		selectRadioButton("Byte");
		setValueText("8");

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchWord() throws Exception {

		goTo(program.getMinAddress());

		selectRadioButton("Word");

		setValueText("20");

		List<Address> addrs = addrs(0x1002cf8, 0x1002d6b);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchWordBackward() throws Exception {

		goTo(0x01002d6e);

		selectRadioButton("Word");

		setValueText("20");

		List<Address> addrs = addrs(0x1002d6b, 0x1002cf8);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testSearchDWord() throws Exception {
		goTo(program.getMinAddress());

		selectRadioButton("DWord");

		setValueText("100");

		List<Address> addrs = addrs(0x1001708, 0x1004100, 0x1004135);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchDWordBackward() throws Exception {
		goTo(0x01005000);

		selectRadioButton("DWord");

		setValueText("100");

		List<Address> addrs = addrs(0x1004135, 0x1004100, 0x1001708);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testSearchQWord() throws Exception {
		goTo(program.getMinAddress());

		selectRadioButton("QWord");

		setValueText("29555302058557541");

		performSearchTest(addrs(0x1004270), "Next");
	}

	@Test
	public void testSearchQWordBackward() throws Exception {

		goTo(program.getMaxAddress());

		selectRadioButton("QWord");

		setValueText("29555302058557541");

		performSearchTest(addrs(0x1004270), "Previous");
	}

	@Test
	public void testSearchFloat() throws Exception {

		goTo(program.getMinAddress());

		selectRadioButton("Float");

		setValueText("7.4027124e-34");

		List<Address> addrs = addrs(0x1004120, 0x1004200, 0x1004247);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchFloatBackward() throws Exception {

		goTo(0x01005000);

		selectRadioButton("Float");

		setValueText("7.4027124e-34");

		List<Address> addrs = addrs(0x1004247, 0x1004200, 0x1004120);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testSearchFloatBackwardAlign8() throws Exception {

		goTo(program.getMaxAddress());

		JTextField alignment = (JTextField) findComponentByName(dialog.getComponent(), "Alignment");
		setText(alignment, "8");

		selectRadioButton("Float");

		setValueText("7.4027124e-34");

		List<Address> addrs = addrs(0x1004200, 0x1004120);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testSearchDouble() throws Exception {

		goTo(program.getMinAddress());

		selectRadioButton("Double");

		setValueText("1.588386874245921e-307");

		List<Address> addrs = addrs(0x1004200);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchDoubleBackward() throws Exception {

		goTo(program.getMaxAddress());

		selectRadioButton("Double");

		setValueText("1.588386874245921e-307");

		List<Address> addrs = addrs(0x1004200);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testSearchAllByte() throws Exception {

		selectRadioButton("Byte");

		setValueText("8");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 5);

		List<Address> addrs = addrs(0x1002d40, 0x1002d5d, 0x1004123, 0x1004203, 0x100424a);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllWord() throws Exception {

		selectRadioButton("Word");

		setValueText("20");

		pressSearchAllButton();
		waitForSearch("Search Memory - ", 2);

		List<Address> addrs = addrs(0x1002cfa, 0x1002d6c);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllWordAlign4() throws Exception {

		JTextField alignment = (JTextField) findComponentByName(dialog.getComponent(), "Alignment");
		setText(alignment, "4");

		selectRadioButton("Word");

		setValueText("20");

		pressSearchAllButton();
		waitForSearch("Search Memory - ", 1);

		checkMarkerSet(addrs(0x1002d6c));
	}

	@Test
	public void testSearchAllDWord() throws Exception {

		selectRadioButton("DWord");

		setValueText("100");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 3);

		List<Address> addrs = addrs(0x1001715, 0x1004100, 0x1004135);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllQWord() throws Exception {

		selectRadioButton("QWord");

		setValueText("29555302058557541");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 1);

		checkMarkerSet(addrs(0x1004270));
	}

	@Test
	public void testSearchAllFloat() throws Exception {

		selectRadioButton("Float");

		setValueText("7.4027124e-34");

		pressSearchAllButton();
		waitForSearch("Search Memory - ", 3);

		List<Address> addrs = addrs(0x1004120, 0x1004200, 0x1004247);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllDouble() throws Exception {

		selectRadioButton("Double");

		setValueText("1.588386874245921e-307");

		pressSearchAllButton();
		waitForSearch("Search Memory - ", 1);

		checkMarkerSet(addrs(0x1004200));
	}

	@Test
	public void testSearchSelectionByte() throws Exception {

		makeSelection(tool, program, range(0x01004000, 0x01005000));

		assertSearchSelectionSelected();

		selectRadioButton("Byte");

		setValueText("8");

		List<Address> addrs = addrs(0x1004123, 0x1004203, 0x100424a);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchSelectionWord() throws Exception {

		makeSelection(tool, program, range(0x01002c00, 0x01002d00));

		assertSearchSelectionSelected();

		selectRadioButton("Word");

		setValueText("20");

		performSearchTest(addrs(0x1002cf8), "Next");
	}

	@Test
	public void testSearchSelectionDWord() throws Exception {

		makeSelection(tool, program, range(0x01004000, 0x01005000));

		assertSearchSelectionSelected();

		selectRadioButton("DWord");

		setValueText("100");

		List<Address> addrs = addrs(0x1004100, 0x1004135);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchSelectionQWord() throws Exception {

		makeSelection(tool, program, range(0x01004000, 0x01005000));

		assertSearchSelectionSelected();

		selectRadioButton("QWord");

		setValueText("29555302058557541");

		performSearchTest(addrs(0x1004270), "Next");

	}

	@Test
	public void testSearchSelectionFloat() throws Exception {

		makeSelection(tool, program, range(0x01004200, 0x01004300));

		assertSearchSelectionSelected();

		selectRadioButton("Float");

		setValueText("7.4027124e-34");

		List<Address> addrs = addrs(0x1004200, 0x1004247);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchSelectionDouble() throws Exception {

		makeSelection(tool, program, range(0x01004000, 0x01005000));

		assertSearchSelectionSelected();

		selectRadioButton("Double");

		setValueText("1.588386874245921e-307");

		performSearchTest(addrs(0x1004200), "Next");

	}

	@Test
	public void testSearchAllInSelection() throws Exception {

		makeSelection(tool, program, range(0x01002cf5, 0x01002d6d));

		assertSearchSelectionSelected();

		selectRadioButton("Byte");

		setValueText("8");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 2);

		List<Address> addrs = addrs(0x1002d40, 0x1002d5d);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchBackwardsInSelection() throws Exception {

		goTo(program.getMaxAddress());

		makeSelection(tool, program, range(0x01004000, 0x01005000));

		assertSearchSelectionSelected();

		selectRadioButton("Double");

		setValueText("1.588386874245921e-307");

		performSearchTest(addrs(0x1004200), "Previous");
	}

//==================================================================================================
// Private Methods	
//==================================================================================================

	@Override
	protected void showMemSearchDialog() {
		super.showMemSearchDialog();
		selectRadioButton("Decimal");
	}

	private JPanel findTitledJPanel(Container container, String title) {
		if (container instanceof JPanel) {
			JPanel p = (JPanel) container;
			Border b = p.getBorder();
			if ((b instanceof TitledBorder) && ((TitledBorder) b).getTitle().equals(title)) {
				return p;
			}
		}
		Container parent = container.getParent();
		while (parent != null) {
			if (parent instanceof JPanel) {
				JPanel p = findTitledJPanel(parent, title);
				if (p != null) {
					return p;
				}
			}
			parent = parent.getParent();
		}
		return null;
	}

}
