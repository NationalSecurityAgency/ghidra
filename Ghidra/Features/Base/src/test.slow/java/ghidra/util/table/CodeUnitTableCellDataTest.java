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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.table.field.CodeUnitTableCellData;

public class CodeUnitTableCellDataTest extends AbstractProgramBasedTest {

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

		int cuOffset = 0;
		int cuCount = 1;
		Address address = addr(TEST_ADDRESS);
		MnemonicFieldLocation location = new MnemonicFieldLocation(program, address);
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_AddressLocation() {

		int cuOffset = 0;
		int cuCount = 1;
		Address address = addr(TEST_ADDRESS);
		AddressFieldLocation location = new AddressFieldLocation(program, address);
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_BytesLocation() {

		int cuOffset = 0;
		int cuCount = 1;
		Address address = addr(TEST_ADDRESS);
		BytesFieldLocation location = new BytesFieldLocation(program, address);
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
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

		int cuOffset = 0;
		int cuCount = 1;
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_OperandLocation() {

		Address address = addr(TEST_ADDRESS);
		int[] componentPath = null;
		Address refAddr = null;
		String rep = MNEMONIC_DISPLAY_STRING;
		int opIndex = 0;
		int charOffset = 0;
		OperandFieldLocation location = new OperandFieldLocation(program, address, componentPath,
			refAddr, rep, opIndex, charOffset);

		int cuOffset = 0;
		int cuCount = 1;
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		assertEquals(MNEMONIC_DISPLAY_STRING, preview);
	}

	@Test
	public void testDisplayString_XRefLocation() {

		int cuOffset = 0;
		int cuCount = 1;
		Address address = addr("01002cf5");
		int[] componentPath = null;
		Address refAddr = addr("01002239");
		int index = 0;
		int charOffset = 0;
		XRefFieldLocation location =
			new XRefFieldLocation(program, address, componentPath, refAddr, index, charOffset);
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
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

		int cuOffset = 0;
		int cuCount = 1;
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();
		assertEquals("PUSH EBP", preview);
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

		int cuOffset = 0;
		int cuCount = 1;
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();

		// this is the mnemonic and operand inside of the structure at field [2]
		assertEquals("ds \"\" (TestStruct.field_0x5)", preview);
	}

	@Test
	public void testDisplayString_AddressLocation_MultipleCodeUnits() {

		int cuOffset = 0;
		int cuCount = 4;
		Address address = addr(TEST_ADDRESS);
		AddressFieldLocation location = new AddressFieldLocation(program, address);
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		//@formatter:off
		String results =
			MNEMONIC_DISPLAY_STRING +
			"\nCALL dword ptr [DAT_0100115c]" +
			"\nMOV ECX,dword ptr [DAT_01008844]" +
			"\nMOV dword ptr [EAX],ECX";
		//@formatter:on
		assertEquals(results, preview);
	}

	@Test
	public void testDisplayString_AddressLocation_MultipleCodeUnits_NegativeCodeUnitOffset() {

		int cuOffset = -3;
		int cuCount = 6;
		Address address = addr(TEST_ADDRESS);
		AddressFieldLocation location = new AddressFieldLocation(program, address);
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();

		// location defaults to the mnemonic display
		//@formatter:off
		String results =
			"CALL dword ptr [MSVCRT.dll___set_app_type]" +
			"\nADD ESP,0x4" +
			"\nMOV dword ptr [DAT_01009938],0xffffffff" +
			"\n" + MNEMONIC_DISPLAY_STRING +
			"\nCALL dword ptr [DAT_0100115c]" +
			"\nMOV ECX,dword ptr [DAT_01008844]";
		//@formatter:on
		assertEquals(results, preview);
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

		int cuOffset = 0;
		int cuCount = 1;
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
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

		int cuOffset = 0;
		int cuCount = 1;
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();

		assertEquals("PUSH EBP", preview);
	}

	@Test
	public void testDisplayString_LabelFieldLocation() {

		Address address = addr("01002d0f");
		String labelText = "LAB_01002d0f";
		LabelFieldLocation location = new LabelFieldLocation(program, address, labelText);

		int cuOffset = 0;
		int cuCount = 1;
		CodeUnitTableCellData data =
			new CodeUnitTableCellData(location, formatter, cuOffset, cuCount);
		String preview = data.getDisplayString();

		assertEquals("XOR EDI,EDI", preview);
	}

}
