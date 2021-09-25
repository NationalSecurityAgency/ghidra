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
package ghidra.util.table;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.util.viewer.field.ArrayElementFieldLocation;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ClassicSampleX86ProgramBuilder;

public class PreviewTableCellDataTest extends AbstractProgramBasedTest {

	private static final String TEST_ADDRESS = "01006462";
	private static final String MNEMONIC_DISPLAY_STRING = "MOV dword ptr [DAT_0100993c],0xffffffff";

	private CodeUnitFormat formatter;

	@Before
	public void setUp() throws Exception {
		initialize();
		formatter = new BrowserCodeUnitFormat(tool);
	}

	@Override
	protected Program getProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		return builder.getProgram();
	}

	@Test
	public void testDisplayString_MnemonicLocation() {

		Address address = addr(TEST_ADDRESS);
		MnemonicFieldLocation location = new MnemonicFieldLocation(program, address);
		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_AddressLocation() {

		Address address = addr(TEST_ADDRESS);
		AddressFieldLocation location = new AddressFieldLocation(program, address);
		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_BytesLocation() {

		Address address = addr(TEST_ADDRESS);
		BytesFieldLocation location = new BytesFieldLocation(program, address);
		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_CommentsLocation() {

		Address address = addr(TEST_ADDRESS);
		int[] componentPath = null;
		String commentText = "Repeatable Comment";
		String[] comment = new String[] { commentText };
		int row = 0;
		int charOffset = 0;
		int commentRow = 0;
		RepeatableCommentFieldLocation location = new RepeatableCommentFieldLocation(program,
			address, componentPath, comment, row, charOffset, commentRow);

		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();
		assertEquals(commentText, preview);
	}

	@Test
	public void testDisplayString_OperandLocation() {

		Address address = addr(TEST_ADDRESS);
		int[] componentPath = null;
		Address refAddr = null;
		String rep = "dword ptr [DAT_0100993c],0xffffffff";
		int opIndex = 0;
		int charOffset = 0;
		OperandFieldLocation location = new OperandFieldLocation(program, address, componentPath,
			refAddr, rep, opIndex, charOffset);

		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_XRefLocation() {

		Address address = addr("01002cf5");
		int[] componentPath = null;
		Address refAddr = addr("01002239");
		int index = 0;
		int charOffset = 0;
		XRefFieldLocation location =
			new XRefFieldLocation(program, address, componentPath, refAddr, index, charOffset);
		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		assertEquals("PUSH EBP", preview);
	}

	@Test
	public void testDisplayString_FunctionLocation() {

		Address address = addr("01002cf5");

		//@formatter:off
		String signature = "undefined ghidra(" +
			"undefined4 param_1, " +
			"undefined4 param_2, " +
			"undefined4 param_3, " +
			"undefined4 param_4, " +
			"undefined4 param_5)";
		//@formatter:on
		FunctionNameFieldLocation location =
			new FunctionNameFieldLocation(program, address, 0, signature, "ghidra");

		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();
		assertEquals(signature, preview);
	}

	@Test
	public void testDisplayString_StructureFieldLocation() {

		StructureDataType struct = new StructureDataType("TestStruct", 0);
		struct.add(new CharDataType());
		struct.add(new StringDataType(), 4);
		struct.add(new TerminatedStringDataType(), 8);
		struct.add(new UnicodeDataType(), 12);

		Address structAddress = addr("f0001302");
		CreateDataCmd cmd = new CreateDataCmd(structAddress, true, struct);
		assertTrue(applyCmd(program, cmd));

		Address address = addr("f0001307");
		int[] componentPath = new int[] { 2 }; // second field
		Address refAddr = null;
		String rep = "\"\",00";
		int opIndex = 0;
		int charOffset = 0;
		OperandFieldLocation location = new OperandFieldLocation(program, address, componentPath,
			refAddr, rep, opIndex, charOffset);

		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		// this is the mnemonic and operand inside of the structure at field [2]
		assertEquals("ds \"\" (TestStruct.field2_0x5)", preview);
	}

	@Test
	public void testDisplayString_LabelLocation() {

		Address address = addr(TEST_ADDRESS);
		int[] componentPath = null;
		Address refAddr = null;
		String rep = "dword ptr [DAT_0100993c],0xffffffff";
		int opIndex = 0;
		int charOffset = 0;
		OperandFieldLocation location = new OperandFieldLocation(program, address, componentPath,
			refAddr, rep, opIndex, charOffset);

		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_VariableFieldLocation() {

		Address address = addr("01002cf5");
		Function function = program.getFunctionManager().getFunctionAt(address);
		Variable variable = function.getParameter(0);
		int offset = 0;
		VariableNameFieldLocation location =
			new VariableNameFieldLocation(program, variable, offset);

		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		assertEquals("undefined4 Stack[0x4]:4 param_1", preview);
	}

	@Test
	public void testDisplayString_LabelFieldLocation() {

		Address address = addr("01002d0f");
		String labelText = "LAB_01002d0f";
		LabelFieldLocation location = new LabelFieldLocation(program, address, labelText);

		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		assertEquals(labelText, preview);
	}

	// 080489ed
	@Test
	public void testDisplayString_ArrayFieldLocation() {

		Integer16DataType intDataType = new Integer16DataType();
		ArrayDataType innerArray = new ArrayDataType(intDataType, 4, 4);
		ArrayDataType parentArray = new ArrayDataType(innerArray, 4, innerArray.getElementLength());

		Address arrayAddress = addr("0100f2f0");
		CreateDataCmd cmd = new CreateDataCmd(arrayAddress, true, parentArray);
		assertTrue(applyCmd(program, cmd));

		int[] componentPath = new int[] { 17 };
		String displayText = "int16 0h (int16[4][0][1])";
		int index = 0;
		int charOffset = 0;
		Address subElementAddress = arrayAddress.add(20);
		ArrayElementFieldLocation location = new ArrayElementFieldLocation(program,
			subElementAddress, componentPath, displayText, index, charOffset);
		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		assertEquals(displayText, preview);
	}

	@Test
	public void testDisplayString_ExternalLocation() throws Exception {

		Address address = AddressSpace.EXTERNAL_SPACE.getAddress(0x00000001);
		ProgramLocation location = new ProgramLocation(program, address);
		PreviewTableCellData data = new PreviewTableCellData(location, formatter);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		assertEquals("?? ??", preview);
	}
}
