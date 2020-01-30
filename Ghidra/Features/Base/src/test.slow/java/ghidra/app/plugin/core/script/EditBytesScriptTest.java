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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.*;

import java.io.File;

import javax.swing.JDialog;
import javax.swing.JTextField;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.test.*;
import ghidra.util.NumericUtilities;

public class EditBytesScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private ProgramBuilder programBuilder;
	private File script;
	private CodeBrowserPlugin cb;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		program = createProgramBuilder();
		tool = env.launchDefaultTool(program);
		cb = env.getPlugin(CodeBrowserPlugin.class);

		ResourceFile resourceFile =
			Application.getModuleFile("Base", "ghidra_scripts/EditBytesScript.java");
		script = resourceFile.getFile(true);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private Program createProgramBuilder() throws Exception {

		programBuilder = new ProgramBuilder("Test", ProgramBuilder._X86);

		programBuilder.createMemory(".text", "0x01001000", 0x6600);
		programBuilder.createMemory(".text", "0x01008000", 0x600);
		programBuilder.createMemory(".text", "0x0100a000", 0x5400);
		programBuilder.createMemory(".text", "0xf0000248", 0xa8);
		programBuilder.createMemory(".text", "0xf0001300", 0x1c);

		ByteDataType db = new ByteDataType();
		WordDataType dw = new WordDataType();
		DWordDataType ddw = new DWordDataType();
		QWordDataType dq = new QWordDataType();
		StringDataType ds = new StringDataType();

		setData("01001021", "74 65 73 74 00", ds);

		setData("010010c5", "62 69 74 65 00", ds);

		setData("010010ed", "68 65 6c 6c 6f 00", ds);

		setData("010010f5", "6f 6e 65 00", ds);
		programBuilder.setBytes("010010f9", "11 00");

		setData("010010fc", "4a 75 6e 65 00", ds);
		setData("01001101", "00", db);

		setData("01001026", "e3 47", dw);
		setData("01001028", "74 65 73 74", ddw);
		setData("0100102c", "01 02 03 04 05 06 07 08", dq);

		setBytes("0100100e", "75 11");

		setBytes("01001010", "5e");

		setBytes("01001012", "33 f6");
		setBytes("01001014", "3b c6");

		setBytes("01001070", "74 0c");
		setData("01001072", "35 d0", dw);

		setBytes("01001017", "73 73");

		setBytes("01001103", "00 00");
		programBuilder.setBytes("01001105", "00");

		programBuilder.setBytes("01001035", "60 72 ff");

		setBytes("01001040", "83 c9 33");
		setBytes("01001043", "66 ab");
		programBuilder.setBytes("01001045", "39");
		setData("01001046", "1d 14", dw);

		setData("01001060", "07", db);
		programBuilder.setBytes("01001061", "a3");
		setBytes("01001062", "0f 95 c0");
		setData("01001065", "eb 23", dw);

		StructureDataType struct = new StructureDataType("fibonacci", 0);
		struct.add(IntegerDataType.dataType);
		setData("010010ac", "05 08 13 21", struct);

		return programBuilder.getProgram();
	}

	//Change bytes in string to make different string of same length
	//initial
	//01001021  74 65 73 74 00  ds  "test",00
	//input: 70 61 73 73
	//expected result
	//01001021  70 61 73 73 00  ds  "pass",00

	@Test
	public void testSingleString() throws Exception {

		Address addr = addr("01001021");

		assertData(addr, 5, "74 65 73 74 00", "ds");

		assertOperands(addr, "\"test\"");

		goTo(tool, program, addr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("70 61 73 73");

		waitForScript(scriptID);

		assertData(addr, 5, "70 61 73 73 00", "ds");

		assertOperands(addr, "\"pass\"");
	}

	//Change byte within string
	//initial
	//010010c5  62 69 74 65 00  ds  "bite",00
	//input: 79 at 010010c6
	//expected result
	//010010c5  62 79 74 65 00  ds  "byte",00

	@Test
	public void testLetterInString() throws Exception {

		Address addr = addr("010010c5");

		assertData(addr, 5, "62 69 74 65 00", "ds");

		assertOperands(addr, "\"bite\"");

		goTo(tool, program, addr.add(1));
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("79");

		waitForScript(scriptID);

		assertData(addr, 5, "62 79 74 65 00", "ds");

		assertOperands(addr, "\"byte\"");
	}

	//Change bytes in string to make different string of longer length by overwriting null
	//terminating byte followed by undefined 00 byte
	//initial
	//010010ed  68 65 6c 6c 6f 00     ds  "hello",00
	//010010f3  00                    ??
	//input: 66 72 69 65 6e 64
	//expected result
	//010010ed  66 72 69 65 6e 64 00  ds  "friend",00

	@Test
	public void testIncreaseStringLength() throws Exception {

		Address dsAddr = addr("010010ed");

		assertData(dsAddr, 6, "68 65 6c 6c 6f 00", "ds");

		assertOperands(dsAddr, "\"hello\"");

		Address undefinedAddr = dsAddr.add(6);
		assertUndefined(undefinedAddr, undefinedAddr, 1, "00");

		goTo(tool, program, dsAddr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("66 72 69 65 6e 64");

		waitForScript(scriptID);

		assertData(dsAddr, 7, "66 72 69 65 6e 64 00", "ds");

		assertOperands(dsAddr, "\"friend\"");
	}

	//Change bytes in string to make different string of longer length by overwriting null
	//terminating byte followed by undefined non-00 byte
	//initial
	//010010f5  6f 6e 65 00        ds   "one",00
	//010010f9  11                        ??
	//010010fa  00                        ??
	//input: 6d 6f 72 65
	//expected result
	//010010ed  6d 6f 72 65 11 00  ds   "more",11,00

	@Test
	public void testStringFollowedByUndefined() throws Exception {

		Address dsAddr = addr("010010f5");

		assertData(dsAddr, 4, "6f 6e 65 00", "ds");

		assertOperands(dsAddr, "\"one\"");

		Address undefinedAddr = dsAddr.add(4);
		assertUndefined(undefinedAddr, undefinedAddr.add(1), 2, "11 00");

		goTo(tool, program, dsAddr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("6d 6f 72 65");

		waitForScript(scriptID);

		assertData(dsAddr, 6, "6d 6f 72 65 11 00", "ds");

		assertOperands(dsAddr, "\"more\",11h");
	}

	//Change bytes in string to make different string of longer length by overwriting null
	//terminating byte followed by defined byte
	//initial
	//010010fc  4a 75 6e 65 00    ds   "June",00
	//01001101  00                db
	//input: 41 70 72 69 6c
	//expected result
	//010010fc  41     ??     41h    A
	//010010fd  70     ??     70h    p
	//010010fe  72     ??     72h    r
	//010010ff  69     ??     69h    i
	//01001100  6c     ??     6Ch    l
	//01001101  00     db     0h

	@Test
	public void testStringFollowedByDefined() throws Exception {

		Address dsAddr = addr("010010fc");

		assertData(dsAddr, 5, "4a 75 6e 65 00", "ds");

		assertOperands(dsAddr, "\"June\"");

		Address dbAddr = dsAddr.add(5);
		assertData(dbAddr, 1, "00", "db");

		goTo(tool, program, dsAddr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("41 70 72 69 6c");

		waitForScript(scriptID);

		assertUndefined(dsAddr, dsAddr.add(4), 5, "41 70 72 69 6c");

		assertData(dbAddr, 1, "00", "db");
	}

	//Change bytes of different datatypes while maintaining the underlying datatype
	//initial
	//01001026  e3 47                     dw
	//01001028  74 65 73 74               ddw
	//0100102c  01 02 03 04 05 06 07 08   dq
	//input: 90 80 70 60 50 40 30 20 10 00
	//expected result
	//01001026  90 80                     dw
	//01001028  70 60 50 40               ddw
	//0100102c  30 20 10 00 05 06 07 08   dq

	@Test
	public void testRangeOfData() throws Exception {

		Address dwAddr = addr("01001026");
		assertData(dwAddr, 2, "e3 47", "dw");

		Address ddwAddr = dwAddr.add(2);
		assertData(ddwAddr, 4, "74 65 73 74", "ddw");

		Address dqAddr = ddwAddr.add(4);
		assertData(dqAddr, 8, "01 02 03 04 05 06 07 08", "dq");

		goTo(tool, program, dwAddr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("90 80 70 60 50 40 30 20 10 00");

		waitForScript(scriptID);

		assertData(dwAddr, 2, "90 80", "dw");

		assertData(ddwAddr, 4, "70 60 50 40", "ddw");

		assertData(dqAddr, 8, "30 20 10 00 05 06 07 08", "dq");
	}

	//Change bytes in instruction to make different instruction of same length
	//initial
	//0100100e  75 11  JNZ
	//input: 6a 00
	//expected result
	//0100100e  6a 00  PUSH

	@Test
	public void testSingleCUInst() throws Exception {

		Address addr = addr("0100100e");

		assertInstruction(addr, 2, "75 11", "JNZ");

		goTo(tool, program, addr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("6a 00");

		waitForScript(scriptID);

		assertInstruction(addr, 2, "6a 00", "PUSH");
	}

	//Change bytes in instruction to make different instruction
	//of longer length followed by undefined
	//initial
	//01001010  5e     POP
	//01001011  00     ??
	//input: ff d3
	//expected result
	//01001010  ff d3  CALL

	@Test
	public void testIncreaseInstLength() throws Exception {

		Address addr = addr("01001010");

		assertInstruction(addr, 1, "5e", "POP");

		assertUndefined(addr.add(1), addr.add(1), 1, "00");

		goTo(tool, program, addr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("ff d3");

		waitForScript(scriptID);

		assertInstruction(addr, 2, "ff d3", "CALL");
	}

	//Change bytes in instruction to make different instruction
	//of longer length followed by another instruction
	//initial
	//01001012  33 f6      XOR
	//01001014  3b c6      CMP
	//input: f6 c1 20
	//expected result
	//01001012 f6 c1 20    TEST
	//does not matter if leftover bytes in initial inst are undefined or disassembled into code

	@Test
	public void testInstFolloweByInst() throws Exception {

		Address inst1Addr = addr("01001012");

		assertInstruction(inst1Addr, 2, "33 f6", "XOR");

		Address inst2Addr = inst1Addr.add(2);
		assertInstruction(inst2Addr, 2, "3b c6", "CMP");

		goTo(tool, program, inst1Addr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("f6 c1 20");

		waitForScript(scriptID);

		assertInstruction(inst1Addr, 3, "f6 c1 20", "TEST");
	}

	//Change bytes in instruction to make different instruction
	//of longer length followed  by data
	//initial
	//01001070  74 0c    JZ
	//01001072  35 d0    dw
	//input: 89 45 fc (MOV)
	//expected result
	//01001070  89       ??
	//01001070  45       ??
	//01001072  fc d0    dw

	@Test
	public void testInstFollowedByData() throws Exception {

		Address instAddr = addr("01001070");
		assertInstruction(instAddr, 2, "74 0c", "JZ");

		Address dwAddr = instAddr.add(2);
		assertData(dwAddr, 2, "35 d0", "dw");

		goTo(tool, program, instAddr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("89 45 fc");

		waitForScript(scriptID);

		assertUndefined(instAddr, instAddr.add(1), 2, "89 45");

		assertData(dwAddr, 2, "fc d0", "dw");
	}

	//Change bytes in instruction to make different instruction of shorter length
	//initial
	//01001017  73 73    JNC
	//input: 66 6c
	//expected result
	//01001017  66 6c    INSB

	@Test
	public void testDecreaseInstLength() throws Exception {

		Address addr = addr("01001017");

		assertInstruction(addr, 2, "73 73", "JNC");

		goTo(tool, program, addr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("66 6c");

		waitForScript(scriptID);

		assertInstruction(addr, 2, "66 6c", "INSB");
	}

	//Change bytes in instruction while leaving following undefined byte that is not
	//in newly created instruction as undefined
	//initial
	//01001103  00 00    ADD
	//01001105  00       ??
	//input: 5f 5f 5f
	//expected result
	//01001103  5f       POP
	//01001104  5f       POP
	//01001105  5f       ??

	@Test
	public void testInstWithoutUndefinedDisassemble() throws Exception {

		Address instAddr = addr("01001103");
		assertInstruction(instAddr, 2, "00 00", "ADD");

		Address undefAddr = instAddr.add(2);
		assertUndefined(undefAddr, undefAddr, 1, "00");

		goTo(tool, program, instAddr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("5f 5f 5f");

		waitForScript(scriptID);

		assertInstruction(instAddr, 1, "5f", "POP");

		assertInstruction(instAddr.add(1), 1, "5f", "POP");

		assertUndefined(undefAddr, undefAddr, 1, "5f");
	}

	//Change undefined bytes to make data or instruction
	//initial
	//01001035  60  ??
	//01001036  72  ??
	//01001037  ff  ??
	//input: 48 85 ff
	//expected result
	//01001035  48  ??
	//01001036  85  ??
	//01001037  ff  ??
	//user must manually make inst (by hitting "d") or data (by hitting "b") at desired location

	@Test
	public void testRangeOfUndefined() throws Exception {

		Address addr = addr("01001035");

		assertUndefined(addr, addr.add(2), 3, "60 72 ff");

		goTo(tool, program, addr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("48 85 ff");

		waitForScript(scriptID);

		assertUndefined(addr, addr.add(2), 3, "48 85 ff");
	}

	//Change bytes for all three cases consecutively starting with inst
	//initial
	//01001040   83 c9 33     OR
	//01001043   66 ab        STOSW
	//01001045   39           ??
	//01001046   1d 14        dw
	//input: 3e c4 7a 34 25 b8 12
	//expected result
	//01001040   3e c4 7a 34  LES
	//01001043   25           ??
	//01001045   b8           ??
	//01001046   12 14        dw

	@Test
	public void testAll3CasesInstStart() throws Exception {

		Address inst1Addr = addr("01001040");
		assertInstruction(inst1Addr, 3, "83 c9 33", "OR");

		Address inst2Addr = inst1Addr.add(3);
		program.flushEvents();
		assertInstruction(inst2Addr, 2, "66 ab", "STOSW");

		Address undefAddr = inst2Addr.add(2);
		assertUndefined(undefAddr, undefAddr, 1, "39");

		Address dataAddr = undefAddr.add(1);
		assertData(dataAddr, 2, "1d 14", "dw");

		goTo(tool, program, inst1Addr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("3e c4 7a 34 25 b8 12");

		waitForScript(scriptID);

		assertInstruction(inst1Addr, 4, "3e c4 7a 34", "LES");

		assertUndefined(inst1Addr.add(4), undefAddr, 2, "25 b8");

		assertData(dataAddr, 2, "12 14", "dw");
	}

	//Change bytes for all three cases consecutively starting with data
	//initial
	//01001060   07            db
	//01001061   a3            ??
	//01001062   0f 95 c0      SETNZ
	//01001065   eb 23         dw
	//input: 8c 05 19 fd 89 35 58
	//expected result
	//01001060   8c            db
	//01001061   05            ??
	//01001062   19 fd         SBB
	//01001064   89            ??
	//01001065   35 58         dw

	@Test
	public void testAll3CasesDataStart() throws Exception {

		Address dbAddr = addr("01001060");
		assertData(dbAddr, 1, "07", "db");

		Address undefinedAddr = dbAddr.add(1);
		assertUndefined(undefinedAddr, undefinedAddr, 1, "a3");

		Address instAddr = undefinedAddr.add(1);
		assertInstruction(instAddr, 3, "0f 95 c0", "SETNZ");

		Address dwAddr = instAddr.add(3);
		assertData(dwAddr, 2, "eb 23", "dw");

		goTo(tool, program, dbAddr);
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("8c 05 19 fd 89 35 58");

		waitForScript(scriptID);

		assertData(dbAddr, 1, "8c", "db");

		assertUndefined(undefinedAddr, undefinedAddr, 1, "05");

		assertInstruction(instAddr, 2, "19 fd", "SBB");

		assertUndefined(instAddr.add(2), instAddr.add(2), 1, "89");

		assertData(dwAddr, 2, "35 58", "dw");
	}

	//Change bytes at the end of a memory block without passing it
	//initial
	//010085ff   00   ??
	//input: 11 22
	//only check the dialog pops up again when too many bytes entered

	@Test
	public void testEndOfMemoryBlock() throws Exception {

		Address addr = addr("010085ff");
		assertUndefined(addr, addr, 1, "00");

		goTo(tool, program, addr);

		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("11 22");

		waitForSwing();

		JDialog error = waitForJDialog("EditBytesScript");
		assertNotNull("Did not find dialog with error message", error);
		pressButtonByText(error, "OK");

		//prompts another dialog because too many bytes were entered above
		//to fit in current memory block
		giveUserInputBytes("11");

		waitForScript(scriptID);
	}

	//Change bytes in structure
	//initial
	//010010ac 05 08 13 21     fibonacci
	//	010010ac 05     ??
	//  010010ad 08     ??
	//  010010ae 13     ??
	//  010010af 21     ??
	//input: 00 01 01 at 010010ad
	//expected result
	//010010ac 05 00 01 01     fibonacci
	//	010010ac 05     ??
	//  010010ad 00     ??
	//  010010ae 01     ??
	//  010010af 01     ??

	@Test
	public void testBytesInStructure() throws Exception {

		Address addr = addr("010010ac");
		assertData(addr, 4, "05 08 13 21", "fibonacci");

		goTo(tool, program, addr.add(1));
		ScriptTaskListener scriptID = env.runScript(script);

		giveUserInputBytes("00 01 01");

		waitForScript(scriptID);

		assertData(addr, 4, "05 00 01 01", "fibonacci");
	}

	private void waitForScript(ScriptTaskListener scriptID) {
		waitForScriptCompletion(scriptID, 100000);
		program.flushEvents();
		waitForBusyTool(tool);
	}

	private void giveUserInputBytes(String byteString) throws Exception {

		JDialog dialog = waitForJDialog("Replace Bytes");
		JTextField textField = findComponent(dialog, JTextField.class);
		setText(textField, byteString);
		pressButtonByText(dialog, "OK");
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	private void assertData(Address addr, int byteCount, String bytes, String mnemonic)
			throws MemoryAccessException {

		assertBytes(addr, byteCount, bytes);
		assertEquals(mnemonic, program.getListing().getDataAt(addr).getMnemonicString());
	}

	private void assertInstruction(Address addr, int byteCount, String bytes, String mnemonic)
			throws MemoryAccessException {

		assertBytes(addr, byteCount, bytes);
		Instruction instructionAt = program.getListing().getInstructionAt(addr);
		assertEquals(byteCount, instructionAt.getLength());
		assertEquals(mnemonic, instructionAt.getMnemonicString());
	}

	private void assertUndefined(Address start, Address end, int byteCount, String bytes)
			throws Exception {

		assertBytes(start, byteCount, bytes);
		assertTrue(program.getListing().isUndefined(start, end));
	}

	private void assertBytes(Address addr, int count, String bytes) throws MemoryAccessException {

		byte[] x = new byte[count];
		program.getMemory().getBytes(addr, x);
		assertEquals(bytes, NumericUtilities.convertBytesToString(x, " "));
	}

	private void assertOperands(Address addr, String text) {
		cb.goToField(addr, "Operands", 0, 0);
		assertEquals(text, cb.getCurrentFieldText());
	}

	private void setData(String addr, String bytes, DataType dt) throws Exception {
		programBuilder.setBytes(addr, bytes);
		programBuilder.applyDataType(addr, dt);
	}

	private void setBytes(String addr, String bytes) throws Exception {
		programBuilder.setBytes(addr, bytes, true);
	}

}
