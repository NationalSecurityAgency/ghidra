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
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class PinnedSymbolTest extends AbstractGhidraHeadlessIntegrationTest {
	private static int EXPECTED_PROCESSOR_SYMBOLS = 9;
	private static int EXPECTED_USER_SYMBOLS = 2;
	private static int ORIGINAL_BOB_ADDRESS = 4;
	private static int ORIGINAL_FUNCTION_ADDRESS = 0xc;

	private Program program;
	private AddressSpace space;
	private int transactionID;
	private SymbolTable symbolTable;

	private Address originalBobAddress;
	private Address originalFunctionAddress;

	public PinnedSymbolTest() {
		super();
	}

	@Test
	public void testMoveImageBase()
			throws AddressOverflowException, LockException, IllegalStateException {

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS);
		assertNotNull(symbolTable.getPrimarySymbol(addr(4)));

		long imageBaseMove = 0x100;
		Address movedBobAddress = originalBobAddress.add(imageBaseMove);
		Address movedFunctionAddress = originalFunctionAddress.add(imageBaseMove);

		program.setImageBase(addr(imageBaseMove), true);

		// expect one new symbol for pinned function
		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS + 1);

		// check bob symbol
		assertNull(symbolTable.getPrimarySymbol(originalBobAddress));
		assertNotNull(symbolTable.getPrimarySymbol(movedBobAddress));

		assertEquals(0, symbolTable.getLabelHistory(originalBobAddress).length);
		assertEquals(1, symbolTable.getLabelHistory(movedBobAddress).length);

		// check function symbol - function should move, but pinned label should remain.
		Symbol symbol = symbolTable.getPrimarySymbol(originalFunctionAddress);
		assertNotNull(symbol);
		assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		assertEquals("MyFunction", symbol.getName());

		symbol = symbolTable.getPrimarySymbol(movedFunctionAddress);
		assertNotNull(symbol);
		assertEquals(SymbolType.FUNCTION, symbol.getSymbolType());
		assertEquals(SourceType.DEFAULT, symbol.getSource());

	}

	@Test
	public void testMoveMemoryBlock()
			throws AddressOverflowException, LockException, IllegalStateException,
			MemoryBlockException, MemoryConflictException, NotFoundException {

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS);
		assertNotNull(symbolTable.getPrimarySymbol(originalBobAddress));

		long moveAmount = 0x200;
		Address movedBobAddress = originalBobAddress.add(moveAmount);
		Address movedFunctionAddress = originalFunctionAddress.add(moveAmount);

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr(0));
		memory.moveBlock(block, addr(moveAmount), TaskMonitorAdapter.DUMMY_MONITOR);

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS + 1);

		// check bob symbol
		assertNull(symbolTable.getPrimarySymbol(originalBobAddress));
		assertNotNull(symbolTable.getPrimarySymbol(movedBobAddress));
		assertEquals(0, symbolTable.getLabelHistory(originalBobAddress).length);
		assertEquals(1, symbolTable.getLabelHistory(movedBobAddress).length);

		// check function symbol - function should move, but pinned label should remain.
		Symbol symbol = symbolTable.getPrimarySymbol(originalFunctionAddress);
		assertNotNull(symbol);
		assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		assertEquals("MyFunction", symbol.getName());
		symbol = symbolTable.getPrimarySymbol(movedFunctionAddress);
		assertNotNull(symbol);
		assertEquals(SymbolType.FUNCTION, symbol.getSymbolType());
		assertEquals(SourceType.DEFAULT, symbol.getSource());

	}

	@Test
	public void testDeleteMemoryBlock() throws LockException {

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + EXPECTED_USER_SYMBOLS);
		assertNotNull(symbolTable.getPrimarySymbol(originalBobAddress));

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr(0));
		memory.removeBlock(block, TaskMonitorAdapter.DUMMY_MONITOR);

		checkProcessorSymbolsInPlace(EXPECTED_PROCESSOR_SYMBOLS + 1);

		// check bob symbol is gone
		assertNull(symbolTable.getPrimarySymbol(originalBobAddress));
		assertEquals(0, symbolTable.getLabelHistory(originalBobAddress).length);

		// check the pinned function symbol is now just a pinned code symbol
		Symbol symbol = symbolTable.getPrimarySymbol(originalFunctionAddress);
		assertNotNull(symbol);
		assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		assertEquals("MyFunction", symbol.getName());
		assertTrue(symbol.isPinned());
	}

	@Test
	public void testMoveMemoryBlockSymbolAlreadyExistsAtDestination() throws Exception {
		long moveAmount = 0x200;
		Address movedBobAddress = originalBobAddress.add(moveAmount);

		symbolTable.createLabel(movedBobAddress, "Joe", SourceType.USER_DEFINED);

		Symbol[] symbolsAtOrig = symbolTable.getSymbols(originalBobAddress);
		assertTrue(symbolsAtOrig[0].isPrimary());

		Symbol[] symbolsAtMoved = symbolTable.getSymbols(movedBobAddress);
		assertTrue(symbolsAtMoved[0].isPrimary());

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr(0));
		memory.moveBlock(block, addr(moveAmount), TaskMonitor.DUMMY);

		symbolsAtOrig = symbolTable.getSymbols(originalBobAddress);
		assertEquals(0, symbolsAtOrig.length);

		symbolsAtMoved = symbolTable.getSymbols(movedBobAddress);
		assertEquals(2, symbolsAtMoved.length);

		assertEquals("Joe", symbolsAtMoved[0].getName());
		assertEquals("Bob", symbolsAtMoved[1].getName());

		assertTrue(symbolsAtMoved[0].isPrimary());  // joe should be primary
		assertTrue(!symbolsAtMoved[1].isPrimary()); // bob should not be primary
	}

	@Test
	public void moveBlockWithFunctionFromOnePinnedSymbolToAnother() throws Exception {
		long moveAmount = 0x100;
		Address functionAddressAfterMove = addr(ORIGINAL_FUNCTION_ADDRESS + moveAmount);
		symbolTable.createLabel(functionAddressAfterMove, "TARGET", SourceType.USER_DEFINED);
		Symbol target = symbolTable.getPrimarySymbol(functionAddressAfterMove);
		target.setPinned(true);

		assertEquals(SymbolType.LABEL, target.getSymbolType());
		assertTrue(target.isPinned());
		
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr(0));
		memory.moveBlock(block, addr(moveAmount), TaskMonitor.DUMMY);

		Symbol result = symbolTable.getPrimarySymbol(functionAddressAfterMove);
		assertEquals(SymbolType.FUNCTION, result.getSymbolType());
		assertEquals("TARGET", result.getName());
		assertTrue(result.isPinned());

		Symbol leftover = symbolTable.getPrimarySymbol(originalFunctionAddress);
		assertEquals(SymbolType.LABEL, leftover.getSymbolType());
		assertEquals("MyFunction", leftover.getName());
		assertTrue(leftover.isPinned());

	}

	@Test
	public void testPinnedStayWhenBlockMovedOnTopOfThem() throws Exception {
		Address moveToAddress = addr(0x200);

		Symbol symbol = symbolTable.createLabel(moveToAddress, "MyPinned", SourceType.USER_DEFINED);
		symbol.setPinned(true);

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr(0));
		memory.moveBlock(block, moveToAddress, TaskMonitor.DUMMY);

		SymbolIterator symbols = symbolTable.getSymbols("MyPinned");
		Symbol s = symbols.next();
		assertEquals(moveToAddress, s.getAddress());

	}

	@Test
	public void testLabelCollision() throws Exception {
		int moveAmount = 0x100;
		Address movedBobAddress = originalBobAddress.add(moveAmount);
		symbolTable.createLabel(movedBobAddress, "Bob", SourceType.USER_DEFINED);

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr(0));
		memory.moveBlock(block, addr(0x100), TaskMonitor.DUMMY);

		Symbol[] symbols = symbolTable.getSymbols(movedBobAddress);
		assertEquals(1, symbols.length);
		assertEquals("Bob", symbols[0].getName());
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
	}

	@Before
	public void setUp() throws Exception {
		Language lang = getZ80_LANGUAGE();
		program = new ProgramDB("z80", lang, lang.getDefaultCompilerSpec(), this);
		symbolTable = program.getSymbolTable();
		space = program.getAddressFactory().getDefaultAddressSpace();

		originalBobAddress = addr(ORIGINAL_BOB_ADDRESS);
		originalFunctionAddress = addr(ORIGINAL_FUNCTION_ADDRESS);

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
		symbolTable.createLabel(originalBobAddress, "Bob", SourceType.USER_DEFINED);
	}

	private void createPinnedFunctionSymbol()
			throws InvalidInputException, OverlappingFunctionException {
		AddressSet set = new AddressSet(originalFunctionAddress);
		Function fun = program.getFunctionManager()
				.createFunction("MyFunction", originalFunctionAddress, set,
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
