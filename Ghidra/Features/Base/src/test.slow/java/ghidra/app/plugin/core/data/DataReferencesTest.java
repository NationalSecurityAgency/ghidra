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
package ghidra.app.plugin.core.data;

import static org.junit.Assert.*;

import org.junit.*;

import docking.widgets.fieldpanel.field.FieldElement;
import ghidra.app.cmd.data.*;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearOptions;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.util.viewer.field.LabelFieldFactory;
import ghidra.app.util.viewer.field.ListingTextField;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.InvalidInputException;

public class DataReferencesTest extends AbstractGhidraHeadedIntegrationTest {

	private static final long EXT_POINTERS_OFFSET = 0x1001000;

	private Program program;
	private TestEnv env;
	private PluginTool tool;

	/**
	 * Sets up the fixture, for example, open a network connection.
	 * This method is called before a test is executed.
	 */
	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		program = buildNotepad();
		tool = env.showTool(program);

		tool.addPlugin(DataPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());

		program.startTransaction("Test");
	}

	private ProgramDB buildNotepad() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._X86, this);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".data", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		builder.createLabel("0x1001018", "ADVAPI32.dll_RegCloseKey");

		builder.setBytes("10046c6", "ff 15 18 10 00 01", true);
		return builder.getProgram();
	}

	@After
	public void tearDown() {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testStructureFieldReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr(EXT_POINTERS_OFFSET + 23));

		Command cmd = new CreateStructureCmd(addr, 24);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr);
		clearFieldNames((Structure) d.getDataType());

		Symbol s = createLabel(addr, "StructA");
		s.setPrimary();

		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < 24; i += 4) {
			Address a = addr(EXT_POINTERS_OFFSET + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("[StructA]", opStr);
				}
				else {
					assertEquals("[StructA.field_0x" + Integer.toHexString(i) + "]", opStr);
				}
			}
		}
	}

	@Test
	public void testArrayElementReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr(EXT_POINTERS_OFFSET + 23));

		Command cmd = new CreateArrayCmd(addr, 6, new Pointer32DataType(), 4);
		cmd.applyTo(program);

		Symbol s = createLabel(addr, "ArrayA");
		s.setPrimary();

		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < 24; i += 4) {
			Address a = addr(EXT_POINTERS_OFFSET + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("[ArrayA]", opStr);
				}
				else {
					assertEquals("[ArrayA[" + i / 4 + "]]", opStr);
				}
			}
		}

	}

	@Test
	public void testStructureArrayFieldReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr(EXT_POINTERS_OFFSET + (4 * 24)));

		Command cmd = new CreateStructureCmd(addr, 24);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr);
		clearFieldNames((Structure) d.getDataType());

		cmd = new CreateArrayCmd(addr, 4, d.getDataType(), d.getLength());
		cmd.applyTo(program);

		Symbol s = createLabel(addr, "ArrayA");
		s.setPrimary();

		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < (4 * 24); i += 4) {
			Address a = addr(EXT_POINTERS_OFFSET + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("dword ptr [ArrayA]", opStr);
				}
				else {
					int e = i / 24;
					int f = i % 24;
					assertEquals(
						"dword ptr [ArrayA[" + e + "].field" + f + "_0x" + Integer.toHexString(f) +
							"]",
						opStr);
				}
			}
		}
	}

	@Test
	public void testStructureArrayElementReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr(EXT_POINTERS_OFFSET + (4 * 24)));

		for (int i = 0; i < 4; i++) {
			Address a = addr(EXT_POINTERS_OFFSET + (i * 24));
			Command cmd = new CreateArrayCmd(a, 6, new Pointer32DataType(), 4);
			cmd.applyTo(program);
		}

		Command cmd = new CreateStructureCmd(addr, 4 * 24);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr);
		clearFieldNames((Structure) d.getDataType());

		Symbol s = createLabel(addr, "StructA");
		s.setPrimary();

		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < (4 * 24); i += 4) {
			Address a = addr(EXT_POINTERS_OFFSET + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("dword ptr [StructA]", opStr);
				}
				else {
					int fOrdinal = i / 24;
					int fOffset = fOrdinal * 24;
					int e = (i % 24) / 4;
					assertEquals(
						"dword ptr [StructA.field" + fOrdinal + "_0x" +
							Integer.toHexString(fOffset) + "[" + e +
							"]]",
						opStr);
				}
			}
		}
	}

	@Test
	public void testCompoundArrayElementReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr(EXT_POINTERS_OFFSET + (4 * 24)));

		Command cmd = new CreateArrayCmd(addr, 6, new Pointer32DataType(), 4);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr);

		cmd = new CreateArrayCmd(addr, 4, d.getDataType(), d.getLength());
		cmd.applyTo(program);

		Symbol s = createLabel(addr, "ArrayA");
		s.setPrimary();

		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < (4 * 24); i += 4) {
			Address a = addr(EXT_POINTERS_OFFSET + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("dword ptr [ArrayA]", opStr);
				}
				else {
					int e1 = i / 24;
					int e2 = (i % 24) / 4;
					assertEquals("dword ptr [ArrayA[" + e1 + "][" + e2 + "]]", opStr);
				}
			}
		}
	}

	@Test
	public void testCompoundStructureFieldReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr(EXT_POINTERS_OFFSET + (4 * 24)));

		Command cmd = new CreateStructureCmd(addr, 24);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr);
		clearFieldNames((Structure) d.getDataType());

		for (int i = 1; i < 4; i++) {
			Address a = addr(EXT_POINTERS_OFFSET + (i * 24));
			cmd = new ClearCmd(new AddressSet(a, a.add(23)));
			cmd.applyTo(program);
			cmd = new CreateDataCmd(a, d.getDataType());
			cmd.applyTo(program);
		}

		cmd = new CreateStructureCmd(addr, 4 * 24);
		cmd.applyTo(program);

		d = program.getListing().getDataAt(addr);
		clearFieldNames((Structure) d.getDataType());

		Symbol s = createLabel(addr, "StructA");
		s.setPrimary();

		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < (4 * 24); i += 4) {
			Address a = addr(EXT_POINTERS_OFFSET + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("dword ptr [StructA]", opStr);
				}
				else {
					int f1Ordinal = i / 24;
					int f1Offset = f1Ordinal * 24;
					int f2 = i % 24;
					assertEquals("dword ptr [StructA.field" + f1Ordinal + "_0x" +
						Integer.toHexString(f1Offset) +
						".field" + f2 + "_0x" + Integer.toHexString(f2) + "]", opStr);
				}
			}
		}
	}

	@Test
	public void testOffcutStructureFieldReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr.add(23));

		Command cmd = new ClearCmd(new AddressSet(addr, addr.add(23)));
		cmd.applyTo(program);

		addr = addr(EXT_POINTERS_OFFSET + 2);
		cmd = new CreateDataBackgroundCmd(new AddressSet(addr, addr.add(23)),
			new Pointer32DataType());
		cmd.applyTo(program);

		cmd = new CreateStructureCmd(addr, 24);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr);
		clearFieldNames((Structure) d.getDataType());

		Symbol s = createLabel(addr, "StructA");
		s.setPrimary();

		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < 20; i++) {
			Address a = addr(EXT_POINTERS_OFFSET + 2 + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("[StructA]", opStr);
				}
				else {
					int f = (i / 4) * 4;
					int offcut = i % 4;
					if (offcut == 0) {
						assertEquals("[StructA.field_0x" + Integer.toHexString(f) + "]", opStr);
					}
					else {
						assertEquals(
							"[StructA.field_0x" + Integer.toHexString(f) + "+" + offcut + "]",
							opStr);
					}
				}
			}
		}

	}

	@Test
	public void testOffcutIntoStructureShowsPreExistingSymbol() throws Exception {
		//
		// This is an odd case.  If you have a symbol and then clear the bytes and lay down data
		// on top of that symbol, the offcut will still show the original symbol.
		//

		Address structAddr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(structAddr, structAddr.add(23));

		Command cmd = new ClearCmd(new AddressSet(structAddr, structAddr.add(23)));
		cmd.applyTo(program);

		structAddr = addr(EXT_POINTERS_OFFSET + 2);
		cmd = new CreateDataBackgroundCmd(new AddressSet(structAddr, structAddr.add(23)),
			new Pointer32DataType());
		cmd.applyTo(program);

		cmd = new CreateStructureCmd(structAddr, 24);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(structAddr);
		clearFieldNames((Structure) d.getDataType());

		Address refFromAddress = addr(0x010046c6);

		Instruction instr = program.getListing().getInstructionAt(refFromAddress);
		assertNotNull(instr);
		String opStr = CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, 0);
		assertEquals("dword ptr [ADVAPI32.dll_RegCloseKey]", opStr);

		CodeBrowserPlugin cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		assertTrue(cbPlugin.goToField(structAddr, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cbPlugin.getCurrentField();

		// this is check all labels at the given
		FieldElement fieldElement = tf.getFieldElement(0, 0);
		assertEquals("ADVAPI32.dll_RegCloseKey (01001002+22)", fieldElement.getText());
	}

	@Test
	public void testOffcutArrayElementReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr.add(23));

		Command cmd = new ClearCmd(new AddressSet(addr, addr.add(23)));
		cmd.applyTo(program);

		addr = addr(EXT_POINTERS_OFFSET + 2);
		cmd = new CreateArrayCmd(addr, 6, new Pointer32DataType(), 4);
		cmd.applyTo(program);

		Symbol s = createLabel(addr, "ArrayA");
		s.setPrimary();

		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < 20; i++) {
			Address a = addr(EXT_POINTERS_OFFSET + 2 + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("[ArrayA]", opStr);
				}
				else {
					int e = i / 4;
					int offcut = i % 4;
					if (offcut == 0) {
						assertEquals("[ArrayA[" + e + "]]", opStr);
					}
					else {
						assertEquals("[ArrayA[" + e + "]+" + offcut + "]", opStr);
					}
				}
			}
		}

	}

	@Test
	public void testOffcutDataReference() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr.add(7));

		Command cmd = new ClearCmd(new AddressSet(addr, addr.add(7)));
		cmd.applyTo(program);

		addr = addr(EXT_POINTERS_OFFSET + 2);
		cmd = new CreateDataCmd(addr, new Pointer32DataType());
		cmd.applyTo(program);

		String primarySymbolName = "MyPtr";
		Symbol s = createLabel(addr, primarySymbolName);
		s.setPrimary();

		checkOffcutLabel(primarySymbolName, primarySymbolName);
	}

	@Test
	public void testOffcutDataReferenceRespondsToLabelChanges_DeletePrimary() throws Exception {

		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr.add(7));

		Command cmd = new ClearCmd(new AddressSet(addr, addr.add(7)));
		cmd.applyTo(program);

		addr = addr(EXT_POINTERS_OFFSET + 2);
		cmd = new CreateDataCmd(addr, new Pointer32DataType());
		cmd.applyTo(program);

		String primarySymbolName = "MyPtr";
		Symbol s = createLabel(addr, primarySymbolName);
		s.setPrimary();
		s.delete();

		checkOffcutLabel("PTR_01001000", "PTR_01001002");
	}

	@Test
	public void testOffcutDataReferenceRespondsToLabelChanges_AddPrimary() throws Exception {
		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr.add(7));

		Command cmd = new ClearCmd(new AddressSet(addr, addr.add(7)));
		cmd.applyTo(program);

		addr = addr(EXT_POINTERS_OFFSET + 2);
		cmd = new CreateDataCmd(addr, new Pointer32DataType());
		cmd.applyTo(program);

		String primarySymbolName = "MyPtr";
		Symbol s = createLabel(addr, primarySymbolName);
		s.setPrimary();

		String newPrimarySymbolName = "new.primary.symbol";
		Symbol newPrimarySymbol = createLabel(addr, newPrimarySymbolName);
		newPrimarySymbol.setPrimary();

		checkOffcutLabel(newPrimarySymbolName, newPrimarySymbolName);
	}

	@Test
	public void testOffcutDataReferenceRespondsToLabelChanges_ChangePrimary() throws Exception {
		Address addr = addr(EXT_POINTERS_OFFSET);
		clearSymbols(addr, addr.add(7));

		Command cmd = new ClearCmd(new AddressSet(addr, addr.add(7)));
		cmd.applyTo(program);

		addr = addr(EXT_POINTERS_OFFSET + 2);
		cmd = new CreateDataCmd(addr, new Pointer32DataType());
		cmd.applyTo(program);

		String primarySymbolName = "MyPtr";
		Symbol s = createLabel(addr, primarySymbolName);
		s.setPrimary();

		String newPrimarySymbolName = "new.primary.symbol";
		s.setName(newPrimarySymbolName, SourceType.USER_DEFINED);

		checkOffcutLabel(newPrimarySymbolName, newPrimarySymbolName);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Symbol createLabel(Address addr, String name) throws InvalidInputException {
		return program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
	}

	private Address addr(long offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	private void clearSymbols(Address start, Address end) {

		ClearOptions options = new ClearOptions(false);
		options.setClearSymbols(true);

		Command cmd = new ClearCmd(new AddressSet(start, end), options);
		cmd.applyTo(program);
	}

	private void clearFieldNames(Structure struct) throws Exception {
		DataTypeComponent[] comps = struct.getComponents();
		for (DataTypeComponent element : comps) {
			element.setFieldName(null);
		}
	}

	private void checkOffcutLabel(String primarySymbolName, String offcutSymbolName) {
		ReferenceManager refMgr = program.getReferenceManager();
		for (int i = 0; i < 4; i++) {
			Address a = addr(EXT_POINTERS_OFFSET + 2 + i);
			ReferenceIterator iter = refMgr.getReferencesTo(a);
			while (iter.hasNext()) {
				Reference ref = iter.next();
				Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
				assertNotNull(instr);
				int opIndex = ref.getOperandIndex();
				String opStr =
					CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, opIndex);
				if (i == 0) {
					assertEquals("[" + primarySymbolName + "]", opStr);
				}
				else {
					assertEquals("[" + offcutSymbolName + "+" + i + "]", opStr);
				}
			}
		}
	}

}
