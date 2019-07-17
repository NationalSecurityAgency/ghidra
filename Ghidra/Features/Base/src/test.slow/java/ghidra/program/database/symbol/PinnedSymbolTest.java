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
package ghidra.program.database.symbol;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.junit.*;

import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressLabelInfo;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class PinnedSymbolTest extends AbstractGhidraHeadlessIntegrationTest {
	private static int EXPECTED_PROCESSOR_SYMBOLS = 9;
	private static int EXPECTED_USER_SYMBOLS = 2;
	private Program program;
	private AddressSpace space;
	private int transactionID;
	private SymbolTable symbolTable;

	public PinnedSymbolTest() {
		super();
	}

	@Test
	public void testMoveImageBase()
			throws AddressOverflowException, LockException, IllegalStateException {

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS);
		assertNotNull(symbolTable.getPrimarySymbol(addr(4)));

		program.setImageBase(addr(0x100), true);

		// expect one new symbol for pinned function
		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS + 1);

		// check bob symbol
		assertNotNull(symbolTable.getPrimarySymbol(addr(0x104)));
		assertEquals(0, symbolTable.getLabelHistory(addr(0x4)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(0x104)).length);

		// check function symbol - function should move, but pinned label should remain.
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0xc));
		assertNotNull(symbol);
		assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		assertEquals("MyFunction", symbol.getName());
		symbol = symbolTable.getPrimarySymbol(addr(0x10c));
		assertNotNull(symbol);
		assertEquals(SymbolType.FUNCTION, symbol.getSymbolType());
		assertEquals(SourceType.DEFAULT, symbol.getSource());

	}

	@Test
	public void testMoveMemoryBlock()
			throws AddressOverflowException, LockException, IllegalStateException,
			MemoryBlockException, MemoryConflictException, NotFoundException {

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS);
		assertNotNull(symbolTable.getPrimarySymbol(addr(4)));

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr(0));
		memory.moveBlock(block, addr(0x200), TaskMonitorAdapter.DUMMY_MONITOR);

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS + 1);

		// check bob symbol
		assertNotNull(symbolTable.getPrimarySymbol(addr(0x204)));
		assertEquals(0, symbolTable.getLabelHistory(addr(0x4)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(0x204)).length);

		// check function symbol - function should move, but pinned label should remain.
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0xc));
		assertNotNull(symbol);
		assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		assertEquals("MyFunction", symbol.getName());
		symbol = symbolTable.getPrimarySymbol(addr(0x20c));
		assertNotNull(symbol);
		assertEquals(SymbolType.FUNCTION, symbol.getSymbolType());
		assertEquals(SourceType.DEFAULT, symbol.getSource());

	}

	@Test
	public void testDeleteMemoryBlock() throws LockException {

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS);
		assertNotNull(symbolTable.getPrimarySymbol(addr(4)));

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr(0));
		memory.removeBlock(block, TaskMonitorAdapter.DUMMY_MONITOR);

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + 1);

		// check bob symbol is gone
		assertNull(symbolTable.getPrimarySymbol(addr(4)));
		assertEquals(0, symbolTable.getLabelHistory(addr(0x4)).length);

		// check the pinned function symbol is now just a pinned code symbol
		Symbol symbol = symbolTable.getPrimarySymbol(addr(0xc));
		assertNotNull(symbol);
		assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		assertEquals("MyFunction", symbol.getName());
		assertTrue(symbol.isPinned());
	}

	private void checkProcessorSymbolsInPlace(int expectedSymbols) {
		assertEquals(expectedSymbols, symbolTable.getNumSymbols());// 8 processor symbols and 2 user defined
		assertNotNull(symbolTable.getPrimarySymbol(addr(0)));
		assertNotNull(symbolTable.getPrimarySymbol(addr(8)));
		assertNotNull(symbolTable.getPrimarySymbol(addr(0x10)));
		assertNotNull(symbolTable.getPrimarySymbol(addr(0x18)));
		assertNotNull(symbolTable.getPrimarySymbol(addr(0x20)));
		assertNotNull(symbolTable.getPrimarySymbol(addr(0x28)));
		assertNotNull(symbolTable.getPrimarySymbol(addr(0x30)));
		assertNotNull(symbolTable.getPrimarySymbol(addr(0x38)));

		assertEquals(1, symbolTable.getLabelHistory(addr(0)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(8)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(0x10)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(0x18)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(0x20)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(0x28)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(0x30)).length);
		assertEquals(1, symbolTable.getLabelHistory(addr(0x38)).length);
	}

	@Before
	public void setUp() throws Exception {
		Language lang = getZ80_LANGUAGE();
		program = new ProgramDB("z80", lang, lang.getDefaultCompilerSpec(), this);
		symbolTable = program.getSymbolTable();
		space = program.getAddressFactory().getDefaultAddressSpace();
		transactionID = program.startTransaction("Test");
		createMemBlock();
		createProcessorSymbols(lang);
		createBobSymbol();
		createPinnedFunctionSymbol();

	}

	private void createProcessorSymbols(Language lang) throws InvalidInputException {
		List<AddressLabelInfo> processorSymbols = lang.getDefaultSymbols();
		for (AddressLabelInfo info : processorSymbols) {
			Symbol symbol =
				symbolTable.createLabel(info.getAddress(), info.getLabel(), SourceType.IMPORTED);
			symbol.setPinned(true);
		}

	}

	private void createBobSymbol() throws InvalidInputException {
		symbolTable.createLabel(addr(4), "Bob", SourceType.USER_DEFINED);
	}

	private void createPinnedFunctionSymbol()
			throws DuplicateNameException, InvalidInputException, OverlappingFunctionException {
		Address addr = addr(0xc);
		AddressSet set = new AddressSet(addr);
		Function fun = program.getFunctionManager().createFunction("MyFunction", addr, set,
			SourceType.USER_DEFINED);
		Symbol symbol = fun.getSymbol();
		symbol.setPinned(true);
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private void createMemBlock() throws Exception {
		byte[] bytesOne = new byte[100];
		TaskMonitor m = TaskMonitorAdapter.DUMMY_MONITOR;
		program.getMemory().createInitializedBlock("B1", addr(0),
			new ByteArrayInputStream(bytesOne), bytesOne.length, m, false);

	}

}
