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
package ghidra.app.cmd.label;

import static org.junit.Assert.*;

import java.util.ArrayList;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * Test deleting labels.
 *
 *
 */
public class DeleteLabelCmdTest extends AbstractGhidraHeadedIntegrationTest {
	private Program notepad;
	private SymbolTable symtab;

	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {

		builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test", "0x0", 10);
		builder.createMemoryReference("0x0", "0x1", RefType.CONDITIONAL_COMPUTED_JUMP,
			SourceType.DEFAULT);
		notepad = builder.getProgram();

		symtab = notepad.getSymbolTable();
	}

	@Test
	public void testDeleteLabel() throws Exception {

		builder.createLabel("0x0", "MyLocal");

		Address addr = addr("0x0");
		SymbolTable symbolTable = notepad.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(addr);
		String name = symbols[0].getName();
		DeleteLabelCmd cmd = new DeleteLabelCmd(addr, name, symbols[0].getParentNamespace());
		assertTrue(applyCmd(notepad, cmd));
		assertNull(getUniqueSymbol(notepad, name));

		// test the undo
		undo(notepad);
		assertNotNull(getUniqueSymbol(notepad, name));
	}

	@Test
	public void testDeleteEntrySymbol() throws Exception {

		builder.createEntryPoint("0x0", "entry");

		SymbolTable symbolTable = notepad.getSymbolTable();
		Symbol symbol = getUniqueSymbol(notepad, "entry");
		assertNotNull(symbol);
		assertTrue(symbolTable.isExternalEntryPoint(symbol.getAddress()));
		DeleteLabelCmd cmd =
			new DeleteLabelCmd(symbol.getAddress(), "entry", symbol.getParentNamespace());
		assertTrue(applyCmd(notepad, cmd));
		assertNull(getUniqueSymbol(notepad, "entry"));
		assertTrue(!symbolTable.isExternalEntryPoint(symbol.getAddress()));

		// test the undo
		undo(notepad);
		assertNotNull(getUniqueSymbol(notepad, "entry"));
		assertTrue(symbolTable.isExternalEntryPoint(symbol.getAddress()));

	}

	@Test
	public void testDeleteGlobalScopeLabel() throws Exception {

		builder.createLabel("0x0", "MyLocal");

		Address addr = addr("0x0");
		SymbolTable symbolTable = notepad.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(addr);
		String name = symbols[0].getName();
		long id = symbols[0].getID();
		DeleteLabelCmd cmd = new DeleteLabelCmd(addr, name, symbols[0].getParentNamespace());
		assertTrue(applyCmd(notepad, cmd));
		assertNull(symbolTable.getSymbol(id));

		// test the undo
		undo(notepad);
		assertNotNull(symbolTable.getSymbol(id));
	}

// Current implementation returns true when deleting a default label with references.
	@Test
	public void testDeleteDefaultLabel() throws Exception {

		Address addr = addr("0x1");
		Symbol origSymbol = symtab.getPrimarySymbol(addr);
		assertEquals(true, origSymbol.getSource() == SourceType.DEFAULT);
		String origName = origSymbol.getName();

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, origName);
		assertEquals(false, applyCmd(notepad, deleteLabelCmd));

		Symbol[] symbols = getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals(origName, symbols[0].getName());
	}

	@Test
	public void testDeleteOnlyLabelWithRefs() throws Exception {

		Address addr = addr("0x1");

		Symbol origSymbol = symtab.getPrimarySymbol(addr);
		assertEquals(true, origSymbol.getSource() == SourceType.DEFAULT);
		String origName = origSymbol.getName();

		Symbol newSymbol = createSymbol(addr, "MySymbol");
		Symbol[] symbols = getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals(newSymbol, symbols[0]);
		assertEquals("MySymbol", symbols[0].getName());

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, "MySymbol");
		assertEquals(true, applyCmd(notepad, deleteLabelCmd));

		symbols = getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals(origName, symbols[0].getName());
	}

	@Test
	public void testDeleteOnlyLabelNoRefs() throws Exception {

		Address addr = addr("0x3");

		Symbol origSymbol = symtab.getPrimarySymbol(addr);
		assertNull(origSymbol);

		Symbol newSymbol = createSymbol(addr, "MySymbol");
		Symbol[] symbols = getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals(newSymbol, symbols[0]);
		assertEquals("MySymbol", symbols[0].getName());

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, "MySymbol");
		assertEquals(true, applyCmd(notepad, deleteLabelCmd));

		symbols = getSymbols(addr);
		assertEquals(0, symbols.length);
	}

	@Test
	public void testDeleteLabelWhereMultiple() throws Exception {

		Address addr = addr("0x1");

		Symbol origSymbol = symtab.getPrimarySymbol(addr);
		assertEquals(true, origSymbol.getSource() == SourceType.DEFAULT);

		createSymbol(addr, "MySymbol");
		createSymbol(addr, "OtherSymbol");
		Symbol[] symbols = getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("MySymbol", symbols[0].getName());
		assertEquals(true, symbols[0].isPrimary());
		assertEquals("OtherSymbol", symbols[1].getName());

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, "MySymbol");
		assertEquals(true, applyCmd(notepad, deleteLabelCmd));

		symbols = getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("OtherSymbol", symbols[0].getName());
	}

	@Test
	public void testDeleteDefaultFunctionLabel() throws Exception {
		// ensure that default function label can not be deleted

		Address addr = addr("0x1");

		String defaultName = SymbolUtilities.getDefaultFunctionName(addr);
		Function function = createFunction(addr);
		assertNotNull(function);
		Symbol[] symbols = getSymbols(addr);
		Symbol functionSymbol = function.getSymbol();
		assertTrue(functionSymbol.getSource() == SourceType.DEFAULT);
		assertEquals(1, symbols.length);
		assertEquals(defaultName, symbols[0].getName());

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, function.getName());
		assertEquals(false, applyCmd(notepad, deleteLabelCmd));

		Symbol primarySymbol = symtab.getPrimarySymbol(addr);
		assertNotNull(primarySymbol);
		assertEquals(primarySymbol, functionSymbol);
	}

	@Test
	public void testDeleteOnlyFunctionLabel() throws Exception {

		Address addr = addr("0x1");

		String defaultName = SymbolUtilities.getDefaultFunctionName(addr);
		Function function = createFunction(addr, "MyFunction");
		assertNotNull(function);
		Symbol[] symbols = getSymbols(addr);
		Symbol functionSymbol = function.getSymbol();
		assertEquals(false, functionSymbol.getSource() == SourceType.DEFAULT);
		assertEquals("MyFunction", functionSymbol.getName());
		assertEquals(1, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, function.getName());
		assertEquals(true, applyCmd(notepad, deleteLabelCmd));

		Symbol primarySymbol = symtab.getPrimarySymbol(addr);
		assertNotNull(primarySymbol);
		assertEquals(defaultName, primarySymbol.getName());
		function = getFunction(addr);
		assertNotNull(function);
		assertEquals(defaultName, function.getSymbol().getName());
	}

	@Test
	public void testDeleteOtherLabelWhereFunction() throws Exception {

		Address addr = addr("0x1");

		Function function = createFunction(addr, "MyFunction");
		assertNotNull(function);
		Symbol[] symbols = getSymbols(addr);
		Symbol functionSymbol = function.getSymbol();
		assertEquals(false, functionSymbol.getSource() == SourceType.DEFAULT);
		assertEquals("MyFunction", functionSymbol.getName());
		assertEquals(1, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());

		createSymbol(addr, "OtherSymbol");
		symbols = getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());
		assertEquals(true, symbols[0].isPrimary());
		assertEquals("OtherSymbol", symbols[1].getName());

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, "OtherSymbol");
		assertEquals(true, applyCmd(notepad, deleteLabelCmd));

		Symbol primarySymbol = symtab.getPrimarySymbol(addr);
		assertNotNull(primarySymbol);
		assertEquals("MyFunction", primarySymbol.getName());
		function = getFunction(addr);
		assertNotNull(function);
		assertEquals("MyFunction", function.getSymbol().getName());
	}

	@Test
	public void testDeleteFunctionLabelWhereMultiple() throws Exception {

		Address addr = addr("0x1");

		Function function = createFunction(addr, "MyFunction");
		assertNotNull(function);
		Symbol[] symbols = getSymbols(addr);
		Symbol functionSymbol = function.getSymbol();
		assertEquals(false, functionSymbol.getSource() == SourceType.DEFAULT);
		assertEquals("MyFunction", functionSymbol.getName());
		assertEquals(1, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());

		createSymbol(addr, "OtherSymbol");
		symbols = getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());
		assertEquals(true, symbols[0].isPrimary());
		assertEquals("OtherSymbol", symbols[1].getName());

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, function.getName());
		assertEquals(true, applyCmd(notepad, deleteLabelCmd));

		Symbol primarySymbol = symtab.getPrimarySymbol(addr);
		assertNotNull(primarySymbol);
		assertEquals("OtherSymbol", primarySymbol.getName());
		function = getFunction(addr);
		assertNotNull(function);
		assertEquals("OtherSymbol", function.getSymbol().getName());
	}

	@Test
	public void testDeleteFunctionLabelWhereOtherHasRefs() throws Exception {

		Address addr = addr("0x1");

		Function function = createFunction(addr, "MyFunction");
		assertNotNull(function);
		Symbol[] symbols = getSymbols(addr);
		Symbol functionSymbol = function.getSymbol();
		assertEquals(false, functionSymbol.getSource() == SourceType.DEFAULT);
		assertEquals("MyFunction", functionSymbol.getName());
		assertEquals(1, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());

		createSymbol(addr, "OtherSymbol");
		createSymbol(addr, "ThirdSymbol");

		symbols = getSymbols(addr);
		assertEquals(3, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());
		assertEquals(true, symbols[0].isPrimary());
		assertEquals("OtherSymbol", symbols[1].getName());
		assertEquals("ThirdSymbol", symbols[2].getName());

		// Add a reference from 01002257 Operand1 to 01002239
		ReferenceManager refMgr = notepad.getReferenceManager();
		Reference ref;
		int txId = notepad.startTransaction("Add Ref and Set Label");
		try {
			ref = refMgr.addMemoryReference(addr("0x01002257"), addr, RefType.DATA,
				SourceType.USER_DEFINED, 1);
			// Set Label to OtherSymbol for above reference.
			refMgr.setAssociation(symbols[2], ref);
		}
		finally {
			notepad.endTransaction(txId, true);
		}
		Reference[] symRefs = getAssociatedReferences(symbols[2]);
		assertEquals(1, symRefs.length);

		DeleteLabelCmd deleteLabelCmd = new DeleteLabelCmd(addr, function.getName());
		assertEquals(true, applyCmd(notepad, deleteLabelCmd));

		Symbol primarySymbol = symtab.getPrimarySymbol(addr);
		assertNotNull(primarySymbol);
		assertEquals("OtherSymbol", primarySymbol.getName());
		function = getFunction(addr);
		assertNotNull(function);
		assertEquals("OtherSymbol", function.getSymbol().getName());
		symRefs = getAssociatedReferences(primarySymbol);
		assertEquals(0, symRefs.length);
	}

	/**
	 * Get memory references associated with a specific symbolID at a specific address.
	 * @param addr symbol address
	 * @param symbolID symbol ID
	 * @return memory references associated with symbol
	 */
	private Reference[] getAssociatedReferences(Symbol s) {
		ReferenceManager refManager = s.getProgram().getReferenceManager();
		ReferenceIterator iter = refManager.getReferencesTo(s.getAddress());
		ArrayList<Reference> list = new ArrayList<>();
		while (iter.hasNext()) {
			Reference ref = iter.next();
			if (s.getID() == ref.getSymbolID()) {
				list.add(ref);
			}
		}
		Reference[] refs = new Reference[list.size()];
		return list.toArray(refs);
	}

	private Symbol createSymbol(Address addr, String name) {
		AddLabelCmd cmd = new AddLabelCmd(addr, name, SourceType.USER_DEFINED);
		return applyCmd(notepad, cmd) ? symtab.getGlobalSymbol(name, addr) : null;
	}

	private Symbol[] getSymbols(Address addr) {
		return symtab.getSymbols(addr);
	}

	private Function createFunction(Address addr) {
		return createFunction(addr, null);
	}

	private Function createFunction(Address addr, String name) {
		CreateFunctionCmd cmd = new CreateFunctionCmd(name, addr, null, SourceType.USER_DEFINED);
		return applyCmd(notepad, cmd) ? getFunction(addr) : null;
	}

	private Function getFunction(Address addr) {
		return notepad.getFunctionManager().getFunctionAt(addr);
	}

	private Address addr(String addrString) {
		return notepad.getAddressFactory().getAddress(addrString);
	}

	private Address addr(long a) {
		return notepad.getAddressFactory().getDefaultAddressSpace().getAddress(a);
	}
}
