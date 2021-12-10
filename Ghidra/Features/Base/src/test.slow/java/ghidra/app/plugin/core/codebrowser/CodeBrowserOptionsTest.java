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

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import org.junit.*;

import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.fieldpanel.field.*;
import generic.test.TestUtils;
import ghidra.GhidraOptions;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.refs.AddMemRefCmd;
import ghidra.app.cmd.refs.AddRegisterRefCmd;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.field.*;
import ghidra.base.help.GhidraHelpService;
import ghidra.framework.cmd.Command;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.BytesFieldLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.HelpLocation;
import util.CollectionUtils;

public class CodeBrowserOptionsTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.launchDefaultTool();
		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() {
		env.closeTool(tool);
		env.dispose();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._X86);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		builder.setBytes("0x1001000", "01 02 03 04 05 06 07 08");
		builder.applyDataType("0x1001000", DWordDataType.dataType);

		builder.setBytes("0x1001100", "01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
		StructureDataType struct = new StructureDataType("struct", 0);
		struct.add(CharDataType.dataType);
		struct.add(IntegerDataType.dataType);
		struct.add(CharDataType.dataType);
		struct.setPackingEnabled(true);
		builder.applyDataType("0x1001100", struct);

		builder.setBytes("0x1001200", "01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
		struct = new StructureDataType("struct2", 12);
		struct.setPackingEnabled(false);
		struct.insertAtOffset(0, CharDataType.dataType, -1);
		struct.insertAtOffset(4, IntegerDataType.dataType, -1);
		struct.insertAtOffset(8, CharDataType.dataType, -1);
		builder.applyDataType("0x1001200", struct);

		builder.setBytes("0x10038b1", "85 c0", true);
		builder.createEmptyFunction("doStuff", "0x10048a3", 50, DataType.DEFAULT);
		DataType dt = new DWordDataType();
		ParameterImpl param = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction("ghidra", "0x1002cf5", 50, DataType.DEFAULT, param, param,
			param, param, param, param);
		builder.setBytes("1002d06", "ff 75 14", true);
		builder.createStackReference("1002d06", RefType.DATA, 0x14, SourceType.ANALYSIS, 0);

		builder.setBytes("1002d0b", "8b f8", true);
		builder.setBytes("1002d0f", "33 ff", true);

		builder.setBytes("10061a7", "ff 35 44 80 00 01", true);

		builder.applyDataType("1003daa", PointerDataType.dataType);
		builder.createExternalReference("1003daa", "TestLib", "ExtNS::ExtLab", 0);

		builder.createEncodedString("0100eee0",
			"This is a line of text used to test the ability to do stuff and  alskdjf  laskjf aslkdjf sdlkfj slfk sdlfkj sldfk s;lkj sdflkj slfj slfj asljf as;lf asfj askljs ",
			StandardCharsets.UTF_16BE, true);

		builder.createMemoryReadReference("1001000", "1003d9f");
		builder.createMemoryReadReference("1001002", "1003d9f");
		builder.createMemoryReadReference("1001004", "1003d9f");
		builder.createMemoryReadReference("1001006", "1003d9f");
		builder.createMemoryReadReference("1001008", "1003d9f");
		builder.createMemoryReadReference("100100a", "1003d9f");
		builder.createMemoryReadReference("100100c", "1003d9f");
		builder.createMemoryReadReference("100100e", "1003d9f");
		builder.createMemoryReadReference("1001010", "1003d9f");

		builder.createMemoryReadReference("1001012", "1003daa");

		builder.setBytes("10048b6", "40", true);
		builder.createMemoryReference("10048ae", "10048b6", RefType.CONDITIONAL_JUMP,
			SourceType.ANALYSIS);

		builder.createMemoryReadReference("1004990", "1008094");
		builder.createMemoryReadReference("1004b74", "1008094");

		return builder.getProgram();
	}

	private void loadProgram() throws Exception {
		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
	}

	private List<String> getOptionNames(Options options, String prefix) {
		List<String> names = options.getOptionNames();
		ArrayList<String> list = new ArrayList<>();
		for (String element : names) {
			if (element.startsWith(prefix)) {
				list.add(element);
			}
		}
		return list;
	}

	@Test
	public void testOptionsHeaders() throws Exception {

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		List<String> names = options.getOptionNames();
		Set<String> map = new HashSet<>();
		for (String element : names) {
			int index = element.indexOf(Options.DELIMITER);
			if (index > 0) { // ignore those at the top level
				map.add(element.substring(0, index));
			}
		}
		String[] groups = new String[map.size()];
		map.toArray(groups);
		Arrays.sort(groups);
		int idx = 0;
		assertEquals("Address Field", groups[idx++]);
		assertEquals("Array Options", groups[idx++]);
		assertEquals("Bytes Field", groups[idx++]);
		assertEquals("Cursor", groups[idx++]);
		assertEquals("Cursor Text Highlight", groups[idx++]);
		assertEquals("EOL Comments Field", groups[idx++]);
		assertEquals("Format Code", groups[idx++]);
		assertEquals("Function Pointers", groups[idx++]);
		assertEquals("Function Signature Field", groups[idx++]);
		assertEquals("Labels Field", groups[idx++]);
		assertEquals("Mnemonic Field", groups[idx++]);
		assertEquals("Mouse", groups[idx++]);
		assertEquals("Operands Field", groups[idx++]);
		assertEquals("Pcode Field", groups[idx++]);
		assertEquals("Plate Comments Field", groups[idx++]);
		assertEquals("Post-comments Field", groups[idx++]);
		assertEquals("Pre-comments Field", groups[idx++]);
		assertEquals("Register Field", groups[idx++]);
		assertEquals("Selection Colors", groups[idx++]);
		assertEquals("XREFs Field", groups[idx++]);
	}

	@Test
	public void testEquals() throws Exception {

		ToolOptions options1 = new ToolOptions("Hi");
		ToolOptions options2 = new ToolOptions("Hi");

		options1.setString("foo", "foo");
		options2.setString("foo", "foo");
		assertEquals(options1, options2);

		options1.setString("foo", "foo1");
		assertFalse(options1.equals(options2));
	}

	@Test
	public void testAddressFieldOptions() throws Exception {

		showTool(tool);
		loadProgram();
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		List<String> names = getOptionNames(options, "Address Field");
		assertEquals(1, names.size());
		assertEquals("Address Field.Address Display Options", names.get(0));
		AddressFieldOptionsWrappedOption afowo =
			(AddressFieldOptionsWrappedOption) options.getCustomOption(names.get(0), null);
		afowo.setShowBlockName(true);
		options.setCustomOption(names.get(0), afowo);

		cb.updateNow();
		cb.goToField(addr("0x1001000"), "Address", 0, 0);
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		String s = btf.getText();
		assertTrue(s.indexOf(":") > 0);
		afowo.setShowBlockName(false);
		options.setCustomOption(names.get(0), afowo);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		s = btf.getText();
		assertTrue(s.indexOf(":") < 0);

		afowo.setMinimumHexDigits(4);
		options.setCustomOption(names.get(0), afowo);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		s = btf.getText();
		assertEquals("1001000", s);

		afowo.setMinimumHexDigits(8);
		options.setCustomOption(names.get(0), afowo);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		s = btf.getText();
		assertEquals("01001000", s);

	}

	@Test
	public void testBytesFieldOptions() throws Exception {

		showTool(tool);
		loadProgram();
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		List<String> names = getOptionNames(options, "Bytes Field");
		assertEquals("Different number of byte options than expected:\n" + names + "\n\n", 6,
			names.size());
		assertEquals("Bytes Field.Byte Group Size", names.get(0));
		assertEquals("Bytes Field.Delimiter", names.get(1));
		assertEquals("Bytes Field.Display Structure Alignment Bytes", names.get(2));
		assertEquals("Bytes Field.Display in Upper Case", names.get(3));
		assertEquals("Bytes Field.Maximum Lines To Display", names.get(4));
		assertEquals("Bytes Field.Reverse Instruction Byte Ordering", names.get(5));

		// option 0 - Byte Group Size
		options.setInt(names.get(0), 2);
		cb.updateNow();
		cb.goToField(addr("0x1001000"), "Bytes", 0, 0);
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0102 0304", btf.getText());

		// option 1 - Delimiter
		options.setString(names.get(1), "-");
		cb.updateNow();
		cb.goToField(addr("0x1001000"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0102-0304", btf.getText());

		// option 2 - Display Structure Alignment Bytes
		//   see separate tests

		// option 3 - Display in Upper Case
		cb.goToField(addr("0x1001100"), "Bytes", 2, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0102-0304-0506-0708-090a-0b0c", btf.getText());

		options.setBoolean(names.get(3), true);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0102-0304-0506-0708-090A-0B0C", btf.getText());

		// option 4 - Maximum Lines To Display
		cb.goToField(addr("0x100aef8"), "Bytes", 0, 0);
		cb.updateNow();
		StructureDataType struct = new StructureDataType("fred", 50);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x100aef8"), struct);
		tool.execute(cmd, program);

		options.setInt(names.get(4), 3);
		cb.updateNow();
		cb.goToField(addr("0x100aef8"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, getNumberOfLines(btf));

		// option 5 - Reverse Instruction Byte Ordering
		cb.goToField(addr("0x10038b1"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();

		assertEquals("85C0", btf.getText());

		options.setBoolean(names.get(5), true);
		cb.updateNow();
		cb.goToField(addr("0x10038b1"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();

		assertEquals("C085", btf.getText());

		options.setBoolean(names.get(5), false);
		cb.updateNow();
		cb.goToField(addr("0x10038b1"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();

		assertEquals("85C0", btf.getText());

	}

	@Test
	public void testBytesFieldOptions_NoDisplayStructureAlignmentBytes() throws Exception {

		showTool(tool);
		loadProgram();

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		options.setBoolean("Bytes Field.Display Structure Alignment Bytes", false);

		Address addr = addr("0x1001100");
		cb.goTo(new BytesFieldLocation(program, addr, addr, new int[] { 1 }, 0)); // causes structure to open

		cb.goToField(addr("0x1001100"), "Bytes", 1, 0, 0);
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertEquals("01", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		FieldElement fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001104"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("05 06 07 08", btf.getText());
		assertEquals(12, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 3);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 6);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 9);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001108"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("09", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
	}

	@Test
	public void testBytesFieldOptions_DisplayStructureAlignmentBytesWithGrouping()
			throws Exception {

		showTool(tool);
		loadProgram();

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		options.setBoolean("Bytes Field.Display Structure Alignment Bytes", true);
		options.setInt("Bytes Field.Byte Group Size", 2);

		Address addr = addr("0x1001100");
		cb.goTo(new BytesFieldLocation(program, addr, addr, new int[] { 1 }, 0)); // causes structure to open

		cb.goToField(addr("0x1001100"), "Bytes", 1, 0, 0);
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0102 0304", btf.getText());
		assertEquals(10, btf.getNumCols(0));
		FieldElement fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 2);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 5);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 7);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001104"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0506 0708", btf.getText());
		assertEquals(10, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 2);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 5);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 7);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001108"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("090a 0b0c", btf.getText());
		assertEquals(10, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 2);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 5);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 7);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
	}

	@Test
	public void testBytesFieldOptions_DisplayStructureAlignmentBytes() throws Exception {

		showTool(tool);
		loadProgram();

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		options.setBoolean("Bytes Field.Display Structure Alignment Bytes", true);

		Address addr = addr("0x1001100");
		cb.goTo(new BytesFieldLocation(program, addr, addr, new int[] { 1 }, 0)); // causes structure to open

		cb.goToField(addr("0x1001100"), "Bytes", 1, 0, 0);
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertEquals("01 02 03 04", btf.getText());
		assertEquals(12, btf.getNumCols(0));
		FieldElement fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 3);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 6);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 9);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001104"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("05 06 07 08", btf.getText());
		assertEquals(12, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 3);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 6);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 9);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001108"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("09 0a 0b 0c", btf.getText());
		assertEquals(12, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 3);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 6);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 9);
		assertEquals(BytesFieldFactory.ALIGNMENT_BYTES_COLOR, fe.getColor(0));
	}

	@Test
	public void testBytesFieldOptions_DisplayUnalignedStructureBytes() throws Exception {

		showTool(tool);
		loadProgram();

		// turn alignment bytes option on but it has no impact on displayed bytes for non-packed structure
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		options.setBoolean("Bytes Field.Display Structure Alignment Bytes", true);

		Address addr = addr("0x1001200");
		cb.goTo(new BytesFieldLocation(program, addr, addr, new int[] { 1 }, 0)); // causes structure to open

		cb.goToField(addr("0x1001200"), "Bytes", 1, 0, 0);
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertEquals("01", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		FieldElement fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001201"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("02", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001202"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("03", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001203"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("04", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001204"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("05 06 07 08", btf.getText());
		assertEquals(12, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 3);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 6);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
		fe = btf.getFieldElement(0, 9);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001208"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("09", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x1001209"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0a", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x100120a"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0b", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));

		cb.goToField(addr("0x100120b"), "Bytes", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("0c", btf.getText());
		assertEquals(3, btf.getNumCols(0));
		fe = btf.getFieldElement(0, 1);
		assertEquals(BytesFieldFactory.DEFAULT_COLOR, fe.getColor(0));
	}

	@SuppressWarnings("unchecked")
	// we know the type here
	private int getNumberOfLines(ListingTextField textField) {
		Field field = (Field) getInstanceField("field", textField);
		if (field instanceof ClippingTextField || field instanceof ReverseClippingTextField) {
			return 1;
		}
		List<Field> subFields = (List<Field>) getInstanceField("subFields", field);
		return subFields.size();
	}

	@Test
	public void testEOLCommentsOptions() throws Exception {

		final int SHOW_AUTO = 0;
		final int SHOW_REF_REPEAT = 1;
		final int SHOW_REPEATABLE = 2;
		final int WORD_WRAP = 3;
		final int MAX_LINES = 4;
		final int SHOW_REF_ADDR = 5;
		//final int SHOW_FUNCTION_AUTO = 6;
		final int SHOW_SEMICOLON = 7;
		showTool(tool);
		loadProgram();
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		List<String> names = getOptionNames(options, "EOL Comments Field");
		assertEquals(9, names.size());
		assertEquals(EolCommentFieldFactory.ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG, names.get(0));
		assertEquals(EolCommentFieldFactory.ENABLE_ALWAYS_SHOW_REF_REPEATABLE_MSG, names.get(1));
		assertEquals(EolCommentFieldFactory.ENABLE_ALWAYS_SHOW_REPEATABLE_MSG, names.get(2));
		assertEquals(EolCommentFieldFactory.ENABLE_WORD_WRAP_MSG, names.get(3));
		assertEquals(EolCommentFieldFactory.MAX_DISPLAY_LINES_MSG, names.get(4));
		assertEquals(EolCommentFieldFactory.ENABLE_PREPEND_REF_ADDRESS_MSG, names.get(5));
		assertEquals(EolCommentFieldFactory.SHOW_FUNCTION_AUTOMITIC_COMMENT_MSG, names.get(6));
		assertEquals(EolCommentFieldFactory.ENABLE_SHOW_SEMICOLON_MSG, names.get(7));
		assertEquals(EolCommentFieldFactory.USE_ABBREVIATED_AUTOMITIC_COMMENT_MSG, names.get(8));

		Address callAddress = addr("0x1003fcc");
		Address callRefAddress = addr("0x1006642");
		Address otherRefAddress = addr("0x1003fa1");

		cb.goToField(callAddress, "Bytes", 0, 0);

		SetCommentCmd eolCmd = new SetCommentCmd(callAddress, CodeUnit.EOL_COMMENT,
			"a bb ccc dddd eeeee ffff ggg hhh ii j k ll mmm nnn oooo " +
				"ppppp qqqq rrrr ssss tttt uuuuu vvvvvv wwwww\n\n\n\n" +
				"AAA BBB CCC DDD EEE FFF GGG HHH III JJJ KKK LLL MMM NNN OOO PPP QQQ " +
				"RRR SSS TTT UUU VVV WWW XXX YYY ZZZZZ\n\n\n\n" +
				"1 22 333 4444 55555 666666 7777777 88888888 999999999 0000000000 1 22 333 " +
				"4444 55555 666666 7777777 88888888 999999999 0000000000 1 22 333 4444 55555");
		tool.execute(eolCmd, program);

		SetCommentCmd repeatCmd = new SetCommentCmd(callAddress, CodeUnit.REPEATABLE_COMMENT,
			"Local repeatable line1.\n" + "\n" + "Line3 of repeatable.");
		tool.execute(repeatCmd, program);

		AddressSet body = new AddressSet(addr("0x01006642"), addr("0x01006647"));
		CreateFunctionCmd createFunctionCmd =
			new CreateFunctionCmd(null, callRefAddress, body, SourceType.USER_DEFINED);
		tool.execute(createFunctionCmd, program);

		SetCommentCmd callRepeatCmd = new SetCommentCmd(callRefAddress, CodeUnit.REPEATABLE_COMMENT,
			"\n" + "Function Repeatable line2");
		tool.execute(callRepeatCmd, program);

		AddMemRefCmd addRefCmd = new AddMemRefCmd(callAddress, otherRefAddress, RefType.DATA,
			SourceType.USER_DEFINED, 0, false);
		tool.execute(addRefCmd, program);

		SetCommentCmd commentRefCmd = new SetCommentCmd(otherRefAddress,
			CodeUnit.REPEATABLE_COMMENT, "Mem ref line1.\n" + "");
		tool.execute(commentRefCmd, program);

		options.setBoolean(names.get(SHOW_AUTO), false);
		options.setBoolean(names.get(SHOW_REF_REPEAT), false);
		options.setBoolean(names.get(SHOW_REPEATABLE), false);
		options.setBoolean(names.get(WORD_WRAP), false);
		options.setInt(names.get(MAX_LINES), 20);
		options.setBoolean(names.get(SHOW_REF_ADDR), false);
		options.setBoolean(names.get(SHOW_SEMICOLON), false);
		cb.updateNow();
		cb.goToField(callAddress, "EOL Comment", 0, 0);
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertEquals(9, getNumberOfLines(btf));

		options.setBoolean(names.get(WORD_WRAP), true);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(18, getNumberOfLines(btf));

		options.setBoolean(names.get(SHOW_SEMICOLON), true);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(20, getNumberOfLines(btf));
		assertEquals("; ", btf.getFieldElement(1, 0).getText());

		options.setBoolean(names.get(SHOW_REPEATABLE), true);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(20, getNumberOfLines(btf));
		assertEquals("; ", btf.getFieldElement(1, 0).getText());

		options.setBoolean(names.get(SHOW_AUTO), true);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(20, getNumberOfLines(btf));
		assertEquals("; ", btf.getFieldElement(1, 0).getText());

		options.setBoolean(names.get(SHOW_REF_REPEAT), true);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(20, getNumberOfLines(btf));
		assertEquals("; ", btf.getFieldElement(1, 0).getText());

		options.setBoolean(names.get(SHOW_REF_ADDR), true);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(20, getNumberOfLines(btf));
		assertEquals("; ", btf.getFieldElement(1, 0).getText());

		options.setBoolean(names.get(SHOW_REPEATABLE), false);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(20, getNumberOfLines(btf));
		assertEquals("; ", btf.getFieldElement(1, 0).getText());

		options.setBoolean(names.get(WORD_WRAP), false);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(12, getNumberOfLines(btf));
		assertTrue("; ".equals(btf.getFieldElement(5, 0).getText()));

		options.setBoolean(names.get(SHOW_SEMICOLON), false);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(12, getNumberOfLines(btf));
		assertFalse("; ".equals(btf.getFieldElement(1, 0).getText()));
		assertEquals("01003fa1", btf.getFieldElement(11, 4).getText());
		assertEquals("Mem ref line1.", btf.getFieldElement(11, 11).getText());

		options.setBoolean(names.get(SHOW_REF_ADDR), false);
		cb.updateNow();
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(11, getNumberOfLines(btf));
		assertFalse("; ".equals(btf.getFieldElement(1, 0).getText()));

		cb.goToField(callAddress, "EOL Comment", 9, 4);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(11, getNumberOfLines(btf));
		assertEquals("Mem ref line1.", btf.getFieldElement(9, 4).getText());
	}

	@Test
	public void testLabelFieldOptions() throws Exception {

		showTool(tool);
		loadProgram();
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		List<String> names = getOptionNames(options, "Labels Field");
		assertEquals("Labels Field.Display Function Label", names.get(0));

		cb.goToField(addr("0x10048a3"), "Address", 0, 0);

		options.setBoolean(names.get(0), false);
		cb.updateNow();
		waitForPostedSwingRunnables();

		assertFalse(cb.goToField(addr("0x10048a3"), "Label", 0, 0));
		options.setBoolean(names.get(0), true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertTrue(cb.goToField(addr("0x10048a3"), "Label", 0, 0));
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertEquals("doStuff", btf.getText());
	}

	@Test
	public void testOperandFieldOptions() throws Exception {

		showTool(tool);
		loadProgram();
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		List<String> names = getOptionNames(options, "Operands Field");
		assertEquals(15, names.size());
		assertEquals("Operands Field.Add Space After Separator", names.get(0));
		assertEquals("Operands Field.Always Show Primary Reference", names.get(1));
		assertEquals("Operands Field.Display Abbreviated Default Label Names", names.get(2));
		assertEquals("Operands Field.Display Namespace", names.get(3));
		assertEquals("Operands Field.Enable Word Wrapping", names.get(4));
		assertEquals("Operands Field.Follow Read or Indirect Pointer References", names.get(5));
		assertEquals("Operands Field.Include Scalar Reference Adjustment", names.get(6));
		assertEquals("Operands Field.Markup Inferred Variable References", names.get(7));
		assertEquals("Operands Field.Markup Register Variable References", names.get(8));
		assertEquals("Operands Field.Markup Stack Variable References", names.get(9));
		assertEquals("Operands Field.Maximum Length of String in Default Labels", names.get(10));
		assertEquals("Operands Field.Maximum Lines To Display", names.get(11));
		assertEquals("Operands Field.Show Block Names", names.get(12));
		assertEquals("Operands Field.Show Offcut Information", names.get(13));
		assertEquals("Operands Field.Underline References", names.get(14));

		NamespaceWrappedOption namespaceOption =
			(NamespaceWrappedOption) options.getCustomOption(names.get(3),
				new NamespaceWrappedOption());

		assertTrue(cb.goToField(addr("0x100eee0"), "Address", 0, 0));
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertEquals(1, getNumberOfLines(btf));

		options.setBoolean(names.get(4), true);
		options.setInt(names.get(11), 4);
		cb.updateNow();

		//--- Verify stack variable markup options

		assertTrue(cb.goToField(addr("0x1002d06"), "Operands", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("dword ptr [EBP + param_5]", btf.getText());

		options.setBoolean(names.get(9), false);
		cb.updateNow();
		cb.goToField(addr("0x1002d06"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("dword ptr [EBP + 0x14]=>param_5", btf.getText());

		//--- Verify register variable markup options

		Command cmd = new AddRegisterRefCmd(addr("0x1002d0b"), 0, program.getRegister("EDI"),
			SourceType.USER_DEFINED);
		applyCmd(program, cmd);
		cb.updateNow();

		assertTrue(cb.goToField(addr("0x1002d0b"), "Operands", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("local_EDI_22,EAX", btf.getText());

		assertTrue(cb.goToField(addr("0x1002d0f"), "Operands", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("local_EDI_22,local_EDI_22", btf.getText()); // inferred register variable mark-up

		options.setBoolean(names.get(7), true);
		cb.updateNow();
		cb.goToField(addr("0x1002d0f"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("local_EDI_22,local_EDI_22", btf.getText());

		options.setBoolean(names.get(8), false);
		cb.updateNow();
		cb.goToField(addr("0x1002d0f"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("EDI,EDI", btf.getText());

		cb.goToField(addr("0x1002d0b"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("EDI=>local_EDI_22,EAX", btf.getText());

		//---------

		cb.goToField(addr("0x100eee0"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(4, getNumberOfLines(btf));

		options.setBoolean(names.get(4), false);
		cb.updateNow();
		cb.goToField(addr("0x100eee0"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(1, getNumberOfLines(btf));

		assertTrue(cb.goToField(addr("0x10061a7"), "Operands", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("dword ptr [DAT_01008044]", btf.getText());

		options.setBoolean(names.get(12), true);
		cb.updateNow();

		cb.goToField(addr("0x10061a7"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("dword ptr [.data:DAT_01008044]", btf.getText());

		//---------

		cb.goToField(addr("0x1003daa"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("TestLib::ExtNS::ExtLab", btf.getText());

		cb.goToField(addr("0x1001012"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("->TestLib::ExtNS::ExtLab", btf.getText());

		namespaceOption.setShowLibraryInNamespace(false);
		options.setCustomOption(names.get(3), namespaceOption);
		cb.updateNow();

		cb.goToField(addr("0x1003daa"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("ExtNS::ExtLab", btf.getText());

		cb.goToField(addr("0x1001012"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("->ExtNS::ExtLab", btf.getText());

		namespaceOption.setShowLibraryInNamespace(true);
		namespaceOption.setShowNonLocalNamespace(false);
		options.setCustomOption(names.get(3), namespaceOption);
		cb.updateNow();

		cb.goToField(addr("0x1003daa"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("ExtLab", btf.getText());

		cb.goToField(addr("0x1001012"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("->ExtLab", btf.getText());

		options.setBoolean(names.get(5), false);
		cb.updateNow();

		cb.goToField(addr("0x1001012"), "Operands", 0, 0);
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("PTR_ExtLab_01003daa", btf.getText());

	}

	@Test
	public void testXrefFieldOptions() throws Exception {

		showTool(tool);
		loadProgram();
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		List<String> names = getOptionNames(options, "XREFs Field");
		assertEquals("XREFs Field.Delimiter", names.get(0));
		assertEquals("XREFs Field.Display Local Block", names.get(1));
		assertEquals("XREFs Field.Display Namespace", names.get(2));
		assertEquals("XREFs Field.Display Reference Type", names.get(3));
		assertEquals("XREFs Field.Group by Function", names.get(4));
		assertEquals("XREFs Field.Maximum Number of XREFs to Display", names.get(5));

		assertTrue(cb.goToField(addr("0x1003d9f"), "XRef", 0, 0));

		// test Delimiter
		options.setString(names.get(0), "/");
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x1003d9f"), "XRef", 0, 0));
		ListingTextField btf = (ListingTextField) cb.getCurrentField();
		assertTrue(btf.getText().indexOf("/") > 0);

		options.setString(names.get(0), ",");
		cb.updateNow();

		// test show function name
		assertTrue(cb.goToField(addr("0x10048b6"), "XRef", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("010048ae(j) ", btf.getFieldElement(0, 0).getText());

		// namespace options
		// -Display non-local
		// -Display local
		// -Use local namespace override
		NamespaceWrappedOption newCustomOption = new NamespaceWrappedOption();

		// show local namespace
		newCustomOption.setShowNonLocalNamespace(false);
		newCustomOption.setShowLocalNamespace(true);
		newCustomOption.setUseLocalPrefixOverride(false);
		options.setCustomOption(names.get(2), newCustomOption);
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x10048b6"), "XRef", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("doStuff:010048ae(j) ", btf.getFieldElement(0, 0).getText());

		// don't show local namespace
		newCustomOption.setShowLocalNamespace(false);
		options.setCustomOption(names.get(2), newCustomOption);
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x10048b6"), "XRef", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("010048ae(j) ", btf.getFieldElement(0, 0).getText());

		// local namespace override
		newCustomOption.setShowLocalNamespace(true);
		newCustomOption.setUseLocalPrefixOverride(true);
		String overrideName = "overrideMe";
		newCustomOption.setLocalPrefixText(overrideName);
		options.setCustomOption(names.get(2), newCustomOption);
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x10048b6"), "XRef", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(overrideName + "010048ae(j) ", btf.getFieldElement(0, 0).getText());

		// test show block name
		options.setBoolean(names.get(1), false);
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x1008094"), "XRef", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals("01004990(R),", btf.getFieldElement(0, 0).getText());

		options.setBoolean(names.get(1), true);
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x1008094"), "XRef", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(".text:01004990(R),", btf.getFieldElement(0, 0).getText());

		// test max Xrefs to display
		assertTrue(cb.goToField(addr("0x1003d9f"), "XRef", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(9, btf.getNumRows());

		// note: the 'group by function' option is tested in the XrefFieldFactoryTest

		options.setInt(names.get(5), 3);
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x1003d9f"), "XRef", 0, 0));
		btf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, btf.getNumRows());
		assertTrue(btf.getText().endsWith("[more]"));
	}

	@Test
	public void testEveryOptionHasHelp() throws Exception {
		showTool(tool);
		loadProgram();
		List<String> missing = new ArrayList<>();
		ToolOptions[] toolOptions = tool.getOptions();
		GhidraHelpService.install();
		for (ToolOptions options : toolOptions) {

			HelpLocation optionsHelp = options.getOptionsHelpLocation();
			boolean hasParentHelp = optionsHelp != null;
			if (CollectionUtils.isOneOf(options.getName(), "Key Bindings", "Listing Display")) {
				continue; // these custom widgets are known to have help
			}

			List<String> optionNames = options.getOptionNames();
			for (String name : optionNames) {

				HelpLocation hl = options.getHelpLocation(name);
				if (hl == null) {
					if (!hasParentHelp) {
						missing.add("Option missing help: " + options.getName() + "." + name);
					}
				}

				List<HelpLocation> nestedHelp = getParentHelpLocations(options, name);
				for (HelpLocation help : nestedHelp) {
					if (help != null && !isValidHelpLocation(help)) {
						missing.add("Bad help location: " + help.toString());
					}
				}

				// it has a help location; is it valid?
				if (hl != null && !isValidHelpLocation(hl)) {
					missing.add(name + "." + name);
				}
			}
		}

		if (!missing.isEmpty()) {
			fail(missing.size() + " Tool Options is missing/invalid help\n" +
				missing.stream().collect(Collectors.joining("\n")));
		}
	}

	private List<HelpLocation> getParentHelpLocations(ToolOptions options, String name) {

		List<HelpLocation> list = new LinkedList<>();
		List<String> parts = CollectionUtils.asList(name.split("\\."));
		Collections.reverse(parts); // put lowest-level first
		for (String optionName : parts) {
			Options parentOption = options.getOptions(optionName);
			HelpLocation help = parentOption.getOptionsHelpLocation();
			list.add(help);
		}
		return list;
	}

	private boolean isValidHelpLocation(HelpLocation helpLocation) {

		HelpService help = Help.getHelpService();
		boolean isValid =
			(boolean) TestUtils.invokeInstanceMethod("isValidHelpLocation", help, helpLocation);
		return isValid;
	}

	enum DUMMY {
		// nothing; just a dummy
	}
}
