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
package ghidra.program.model.symbol;

import static org.junit.Assert.assertEquals;

import org.junit.*;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.*;
import ghidra.util.task.TaskMonitorAdapter;

public class SymbolUtilities2Test extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private AddressSpace space;
	private int transactionID;
	private SymbolTable symbolTable;
	private ReferenceManager refMgr;
	private Listing listing;

	public SymbolUtilities2Test() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		TestEnv env = new TestEnv();
		LanguageService ls = DefaultLanguageService.getLanguageService();
		Language i8051 = ls.getDefaultLanguage(TestProcessorConstants.PROCESSOR_8051);
		program = new ProgramDB("Test", i8051, i8051.getDefaultCompilerSpec(), this);
		env.dispose();
		space = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		transactionID = program.startTransaction("Test");
		memory.createInitializedBlock("test", addr(0), 5000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
		symbolTable = program.getSymbolTable();
		refMgr = program.getReferenceManager();
		listing = program.getListing();
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(transactionID, true);
			program.release(this);
		}
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	@Test
	public void testDynamicLabelFlowToUndefined() {
		refMgr.addMemoryReference(addr(0x100), addr(0x200), RefType.FLOW, SourceType.USER_DEFINED,
			-1);
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0x200));
		assertEquals("LAB_CODE_0200", symbol.getName());
	}

	@Test
	public void testDynamicLabelReadToUndefined() {
		refMgr.addMemoryReference(addr(0x100), addr(0x200), RefType.READ, SourceType.USER_DEFINED,
			-1);
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0x200));
		assertEquals("DAT_CODE_0200", symbol.getName());

	}

	@Test
	public void testDynamicLabelReadToCode() throws Exception {
		refMgr.addMemoryReference(addr(0x100), addr(0x200), RefType.READ, SourceType.USER_DEFINED,
			-1);
		ProcessorContext context =
			new ProgramProcessorContext(program.getProgramContext(), addr(0x200));
		DumbMemBufferImpl membuf = new DumbMemBufferImpl(program.getMemory(), addr(0x200));
		InstructionPrototype proto = program.getLanguage().parse(membuf, context, false);
		listing.createInstruction(addr(0x200), proto, membuf, context);
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0x200));
		assertEquals("LAB_CODE_0200", symbol.getName());

	}

	@Test
	public void testDynamicLabelFlowToByte() throws Exception {
		refMgr.addMemoryReference(addr(0x100), addr(0x200), RefType.FLOW, SourceType.USER_DEFINED,
			-1);
		listing.createData(addr(0x200), new ByteDataType());
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0x200));
		assertEquals("BYTE_CODE_0200", symbol.getName());
	}

	@Test
	public void testDynamicLabelFlowToWord() throws Exception {
		refMgr.addMemoryReference(addr(0x100), addr(0x200), RefType.FLOW, SourceType.USER_DEFINED,
			-1);
		listing.createData(addr(0x200), new WordDataType());
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0x200));
		assertEquals("WORD_CODE_0200", symbol.getName());
	}

	@Test
	public void testDynamicLabelFlowToString() throws Exception {
		refMgr.addMemoryReference(addr(0x100), addr(0x200), RefType.FLOW, SourceType.USER_DEFINED,
			-1);
		listing.createData(addr(0x200), new StringDataType(), 1);
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0x200));
		assertEquals("s__CODE_0200", symbol.getName());
	}

	@Test
	public void testParseDynamicName() {
		assertEquals(addr(0x100),
			SymbolUtilities.parseDynamicName(program.getAddressFactory(), "LAB_CODE_0100"));
		assertEquals(addr(0x100),
			SymbolUtilities.parseDynamicName(program.getAddressFactory(), "s_foo_CODE_0100"));
		AddressSpace intmemSpace = program.getAddressFactory().getAddressSpace("INTMEM");
		Address address = intmemSpace.getAddress(0x5);
		assertEquals(address,
			SymbolUtilities.parseDynamicName(program.getAddressFactory(), "BYTE_05h_INTMEM_0005"));
	}
}
