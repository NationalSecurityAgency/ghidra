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
package ghidra.app.script;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import ghidra.util.task.TaskMonitorAdapter;

public class GhidraScriptRealProgramTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private GhidraState state;
	private int transactionID;

	public GhidraScriptRealProgramTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();

		PluginTool tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GhidraScriptMgrPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		builder.dispose();

		ProgramLocation loc = new ProgramLocation(program, program.getMinAddress());

		state = new GhidraState(env.getTool(), env.getProject(), program, loc, null, null);
		transactionID = program.startTransaction(testName.getMethodName());
	}

	@After
	public void tearDown() throws Exception {

		program.endTransaction(transactionID, false);

		env.dispose();
		waitForPostedSwingRunnables();
	}

	@Test
	public void testFindByte() throws Exception {
		GhidraScript script = getScript();
		Address address1000 = script.toAddr(0x01001000);
		byte bytePattern1 = (byte) 0x4d;
		assertEquals(addr(0x010022c0), script.find(address1000, bytePattern1));

		Address address6420 = script.toAddr(0x01006420);
		byte bytePattern2 = (byte) 0x68;
		assertEquals(addr(0x01006425), script.find(address6420, bytePattern2));

		String bytePattern1String = "\\x4d";
		Address resultAddress = script.findBytes(address1000, bytePattern1String);
		assertNotNull("Could not find byte pattern " + bytePattern1String, resultAddress);
		assertEquals(addr(0x010022c0), resultAddress);

		String bytePattern2String = "\\x68";
		resultAddress = script.findBytes(address6420, bytePattern2String);
		assertNotNull("Could not find byte pattern " + bytePattern2String, resultAddress);
		assertEquals(addr(0x01006425), resultAddress);

		String regexBytePattern = "\\x4d.{0,10}";
		resultAddress = script.findBytes(null, regexBytePattern);
		assertNotNull("Could not find byte pattern " + regexBytePattern, resultAddress);
		assertEquals(addr(0x010022c0), resultAddress);
	}

	@Test
	public void testFindBytes() throws Exception {
		GhidraScript script = getScript();
		byte[] byteValues1 = new byte[] { (byte) 0x8b, (byte) 0x4d, (byte) 0x08 };
		Address address1000 = script.toAddr(0x01001000);
		assertEquals(addr(0x010022bf), script.find(address1000, byteValues1));

		byte[] byteValues2 = new byte[] { (byte) 0x68, (byte) 0x88, (byte) 0x18, (byte) 0x00 };
		assertEquals(addr(0x01006425), script.find(script.toAddr(0x01006420), byteValues2));

		String byteValues1String = "\\x8b\\x4d\\x08";
		Address result = script.findBytes(address1000, byteValues1String);
		assertEquals(addr(0x010022bf), result);

		String byteValues2String = "\\x4d.{2}";
		result = script.findBytes(address1000, byteValues2String);
		assertEquals(addr(0x010022c0), result);

		Address[] results = script.findBytes(null, byteValues2String, 500);
		assertNotNull(results);
		assertTrue(results.length > 1);
	}

	@Test
	public void testFindBytesInSet() throws Exception {
		GhidraScript script = getScript();
		Address start = script.toAddr(0x1006420);
		Address end = script.toAddr(0x1006458);
		AddressSet set = new AddressSet();
		set.addRange(start, end);
		String byteValues1String = "\\x00\\x01";
		Address[] results = script.findBytes(set, byteValues1String, 20, 1);

		assertEquals(3, results.length);
		assertEquals(script.toAddr(0x1006428), results[0]);
		assertEquals(script.toAddr(0x100642d), results[1]);
		assertEquals(script.toAddr(0x1006453), results[2]);
	}

	@Test
	public void testFindBytesInMultiSet() throws Exception {
		GhidraScript script = getScript();

		AddressSet set = new AddressSet();
		set.addRange(script.toAddr(0x01006425), script.toAddr(0x0100642a));
		set.addRange(script.toAddr(0x0100642c), script.toAddr(0x0100642f));
		set.addRange(script.toAddr(0x0100644f), script.toAddr(0x01006455));

		String byteString = "\\x00\\x01";

		Address[] results = script.findBytes(set, byteString, 20, 1);

		assertEquals(3, results.length);
		assertEquals(script.toAddr(0x1006428), results[0]);
		assertEquals(script.toAddr(0x100642d), results[1]);
		assertEquals(script.toAddr(0x1006453), results[2]);

	}

	@Test
	public void testFindBytesAcrossGap() throws Exception {
		GhidraScript script = getScript();

		AddressSet set = new AddressSet();

		//Match charAt 0x010064db, 0x010064df 
		set.addRange(script.toAddr(0x10064d5), script.toAddr(0x010064db));
		set.addRange(script.toAddr(0x010064df), script.toAddr(0x010064e3));

		String byteString = "\\x51\\x52";

		Address[] results = script.findBytes(set, byteString, 20, 1, true);

		assertEquals(1, results.length);
		assertEquals(script.toAddr(0x010064db), results[0]);

	}

	@Test
	public void testFindText() throws Exception {
		GhidraScript script = getScript();
		Address expected = script.toAddr(0x01001160);
		Address actual = script.find("_app_");
		assertEquals(expected, actual);
	}

	@Test
	public void testNextPrevSymbol() throws Exception {
		GhidraScript script = getScript();

		Symbol symbol = script.getSymbolAfter(script.toAddr(0x1002cf4));
		assertNotNull(symbol);
		assertEquals("ghidra", symbol.getName());

		symbol = script.getSymbolAfter(symbol);
		assertNotNull(symbol);
		assertEquals("MyLocal", symbol.getName());

		symbol = script.getSymbolAfter(symbol.getAddress());
		assertNotNull(symbol);
		assertEquals("AnotherLocal", symbol.getName());

		symbol = script.getSymbolBefore(script.toAddr(0x1004900));
		assertNotNull(symbol);
		assertEquals("doStuff", symbol.getName());

		symbol = script.getSymbolBefore(symbol);
		assertNotNull(symbol);
		assertEquals("FUN_010041fc", symbol.getName());

		symbol = script.getSymbolBefore(symbol);
		assertNotNull(symbol);
		assertEquals("sscanf", symbol.getName());
	}

	@Test
	public void testEquates() throws Exception {
		GhidraScript script = getScript();

		Instruction instruction = script.getInstructionAt(addr("0x1006436"));
		assertEquals(0, script.getEquates(instruction, 0).size());
		Equate equate = script.createEquate(instruction, 0, "zero");
		assertNotNull(equate);
		equate.addReference(script.toAddr(0x1006436), 0);
		assertEquals(1, script.getEquates(instruction, 0).size());
		try {
			script.removeEquates(instruction, 0);
		}
		catch (Exception e) {
			Assert.fail();
		}
		assertEquals(0, script.getEquates(instruction, 0).size());

		instruction = script.getInstructionAt(script.toAddr(0x100644d));
		assertEquals(1, script.getEquates(instruction, 0).size());
		equate = script.getEquates(instruction, 0).get(0);
		assertNotNull(equate);
		assertEquals("TWO", equate.getName());
		assertEquals(0x2, equate.getValue());

		Data data = script.getDataAt(script.toAddr(0x100f204));
		assertNull(script.getEquate(data));
		equate = script.createEquate(data, "QWordValue");
		assertNotNull(equate);
		assertEquals("QWordValue", equate.getName());
		assertEquals(0x690064006e0065L, equate.getValue());
		try {
			script.removeEquate(data);
		}
		catch (Exception e) {
			Assert.fail();
		}
		assertNull(script.getEquate(data));
	}

	@Test
	public void testMemoryReferences() throws Exception {
		GhidraScript script = getScript();
		Address addr1 = script.toAddr(0x01006435);
		Address addr2 = script.toAddr(0xabcd1234);
		Address addr3 = script.toAddr(0xdeadface);
		Instruction instruction = script.getInstructionAt(addr1);
		Reference reference =
			script.createMemoryReference(instruction, 0, addr2, RefType.COMPUTED_CALL);
		assertNotNull(reference);
		assertTrue(reference.isPrimary());
		assertTrue(reference.isMemoryReference());
		assertEquals(RefType.COMPUTED_CALL, reference.getReferenceType());
		boolean found = false;
		for (Reference ref : script.getReferencesFrom(addr1)) {
			if (ref.equals(reference)) {
				found = true;
				break;
			}
		}
		assertTrue(found);
		script.removeReference(reference);
		for (Reference ref : script.getReferencesFrom(addr1)) {
			if (ref.equals(reference)) {
				Assert.fail();
			}
		}
		Reference reference1 =
			script.createMemoryReference(instruction, 0, addr2, RefType.COMPUTED_CALL);
		Reference reference2 =
			script.createMemoryReference(instruction, 0, addr3, RefType.COMPUTED_JUMP);
		assertEquals(2, script.getReferencesFrom(addr1).length);
		assertTrue(reference1.isPrimary());
		assertTrue(!reference2.isPrimary());
		script.setReferencePrimary(reference2);
		reference1 = script.getReference(instruction, addr2);
		reference2 = script.getReference(instruction, addr3);
		assertTrue(!reference1.isPrimary());
		assertTrue(reference2.isPrimary());
	}

	@Test
	public void testExternalReferences() throws Exception {
		GhidraScript script = getScript();
		Address addr1 = script.toAddr(0x010064a3);
		Address addr2 = script.toAddr(0xfeedface);
		Instruction instruction = script.getInstructionAt(addr1);
		Reference reference = script.createExternalReference(instruction, 0, "MyLibraryIsCool.dll",
			"MyLibraryFunction", addr2);
		assertNotNull(reference);
		assertTrue(reference.isPrimary());
		assertTrue(reference.isExternalReference());
		ExternalReference externalReference = (ExternalReference) reference;
		ExternalLocation externalLocation = externalReference.getExternalLocation();
		assertEquals("MyLibraryIsCool.dll", externalLocation.getLibraryName());
		assertEquals("MyLibraryFunction", externalLocation.getLabel());
		assertEquals(addr2, externalLocation.getAddress());
		boolean found = false;
		for (Reference ref : script.getReferencesFrom(addr1)) {
			if (ref.equals(reference)) {
				found = true;
				break;
			}
		}
		assertTrue(found);
		script.removeReference(reference);
		for (Reference ref : script.getReferencesFrom(addr1)) {
			if (ref.equals(reference)) {
				Assert.fail();
			}
		}
	}

	@Test
	public void testStackReferences() throws Exception {
		GhidraScript script = getScript();
		Address entryPoint = script.toAddr(0x01006420);
		script.createFunction(entryPoint, "entry");
		Address addr1 = script.toAddr(0x010064dc);
		Instruction instruction = script.getInstructionAt(addr1);
		Reference reference = script.createStackReference(instruction, 1, -0x64, true);
		assertNotNull(reference);
		assertTrue(reference.isPrimary());
		assertTrue(reference.isStackReference());
		assertEquals(RefType.WRITE, reference.getReferenceType());
		StackReference stackReference = (StackReference) reference;
		assertEquals(-0x64, stackReference.getStackOffset());
		assertEquals(1, stackReference.getOperandIndex());
		boolean found = false;
		for (Reference ref : script.getReferencesFrom(addr1)) {
			if (ref.equals(reference)) {
				found = true;
				break;
			}
		}
		assertTrue(found);
		script.removeReference(reference);
		for (Reference ref : script.getReferencesFrom(addr1)) {
			if (ref.equals(reference)) {
				Assert.fail();
			}
		}
		reference = script.createStackReference(instruction, 1, 0xdeadbeef, false);
		assertEquals(RefType.READ, reference.getReferenceType());
	}

	@Test
	public void testCreateData() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x0100750e);
		Data data = null;

		data = script.createByte(address);
		assertNotNull(data);
		assertEquals(new Scalar(8, 0x52), data.getValue());
		script.clearListing(address);

		data = script.createWord(address);
		assertNotNull(data);
		assertEquals(new Scalar(16, 0x6552), data.getValue());
		script.clearListing(address);

		data = script.createDWord(address);
		assertNotNull(data);
		assertEquals(new Scalar(32, 0x69676552), data.getValue());
		script.clearListing(address);

		data = script.createQWord(address);
		assertNotNull(data);
		assertEquals(new Scalar(64, 0x7265747369676552L), data.getValue());
		script.clearListing(address);

		data = script.createAsciiString(address);
		assertNotNull(data);
		assertEquals("RegisterClassExW", data.getValue());
		script.clearListing(address);

		data = script.createUnicodeString(script.toAddr(0x01001484));
		assertNotNull(data);
		assertEquals("iWindowPosDX", data.getValue());
		script.clearListing(address);

		address = script.toAddr(0x010085a7);
		data = script.createFloat(address);
		assertNotNull(data);
		assertEquals(-1.4682312f, data.getValue());
		script.clearListing(address);

		address = script.toAddr(0x010085a9);
		data = script.createDouble(address);
		assertNotNull(data);
		assertEquals(-8.373196719664668E298, data.getValue());
		script.clearListing(address);
	}

	private GhidraScript getScript() {
		GhidraScript script = new GhidraScript() {
			@Override
			public void run() throws Exception {
				// test stub
			}
		};
		script.set(state, TaskMonitorAdapter.DUMMY_MONITOR, null);
		return script;
	}

	private Address addr(String addr) {
		return program.getAddressFactory().getAddress(addr);
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getAddress(Long.toHexString(offset));
	}

}
