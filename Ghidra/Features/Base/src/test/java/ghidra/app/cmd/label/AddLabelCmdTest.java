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

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.cmd.Command;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;

public class AddLabelCmdTest extends AbstractGenericTest {

	private Program notepad;

	/**
	 * Constructor for LabelTests.
	 * @param name
	 */
	public AddLabelCmdTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test", "0x0", 10);
		notepad = builder.getProgram();
	}

	@Test
	public void testAddLabel() {
		testAddLabel(notepad);
	}

	@Test
	public void testAddBigLabel() {
		String name = makeName(SymbolUtilities.MAX_SYMBOL_NAME_LENGTH);
		Symbol s = testAddLabel(notepad, addr(0x0), name);
		assertNotNull(s);
		assertEquals(name, s.getName());
	}

	@Test
	public void testAddLabelTooBig() {
		String name = makeName(SymbolUtilities.MAX_SYMBOL_NAME_LENGTH + 1);
		Symbol s = testAddLabel(notepad, addr(0x0), name);
		assertNull(s);
	}

	@Test
	public void testAddInvalidLabel() {

		Symbol s = testAddLabel(notepad, addr(0x0), "foo bar");
		assertNull(s);

		StringBuilder buf = new StringBuilder();
		buf.append("foo");
		buf.append('\n');
		testAddLabel(notepad, addr(0x0), buf.toString());
		assertNull(s);
	}

	@Test
	public void testAddLabelAtFunction() throws Exception {

		Function function = getTestFunction();

		int transactionID = notepad.startTransaction("test");
		try {
			function.setName("joe", SourceType.ANALYSIS);
		}
		finally {
			notepad.endTransaction(transactionID, true);
		}

		// add a label
		AddLabelCmd cmd = new AddLabelCmd(addr(0x0), "fred", SourceType.USER_DEFINED);
		execute(cmd);
		Symbol symbol = getUniqueSymbol(notepad, "fred", null);
		assertNotNull(symbol);
		assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		SetLabelPrimaryCmd c =
			new SetLabelPrimaryCmd(symbol.getAddress(), "fred", symbol.getParentNamespace());
		execute(c);

		symbol = getUniqueSymbol(notepad, "fred", null);
		assertEquals(SymbolType.FUNCTION, symbol.getSymbolType());
		assertTrue(symbol.isPrimary());
		assertEquals(SourceType.USER_DEFINED, symbol.getSource());
		function = notepad.getFunctionManager().getFunctionAt(addr(0x0));
		assertEquals("fred", function.getName());

		Symbol other = getUniqueSymbol(notepad, "joe", null);
		assertNotNull(other);
		assertEquals(SourceType.ANALYSIS, other.getSource());
	}

	@Test
	public void testAddNamespaceLabelAtFunction() throws Exception {

		Function function = getTestFunction();
		Namespace ns = null;
		int transactionID = notepad.startTransaction("test");
		try {
			function.setName("joe", SourceType.ANALYSIS);// in the global namespace
			ns = notepad.getSymbolTable().createNameSpace(null, "myNamespace", SourceType.ANALYSIS);
		}
		finally {
			notepad.endTransaction(transactionID, true);
		}

		// add a label
		AddLabelCmd cmd = new AddLabelCmd(addr(0x0), "fred", ns, SourceType.USER_DEFINED);
		execute(cmd);
		Symbol symbol = getUniqueSymbol(notepad, "fred", ns);
		assertNotNull(symbol);
		assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		SetLabelPrimaryCmd c =
			new SetLabelPrimaryCmd(symbol.getAddress(), "fred", symbol.getParentNamespace());
		execute(c);
		symbol = getUniqueSymbol(notepad, "fred", ns);
		assertEquals(SymbolType.FUNCTION, symbol.getSymbolType());
		assertTrue(symbol.isPrimary());
		assertEquals(SourceType.USER_DEFINED, symbol.getSource());
		assertEquals(ns, symbol.getParentNamespace());

		function = notepad.getFunctionManager().getFunctionAt(addr(0x0));
		assertEquals("fred", function.getName());

		Symbol other = getUniqueSymbol(notepad, "joe", null);
		assertNotNull(other);
		assertEquals(SourceType.ANALYSIS, other.getSource());
		assertNull(getUniqueSymbol(notepad, "joe", ns));
	}

	public Symbol getUniqueSymbol(Program program, String name, Namespace namespace) {
		List<Symbol> symbols = program.getSymbolTable().getSymbols(name, namespace);
		if (symbols.size() == 1) {
			return symbols.get(0);
		}
		return null;
	}

	@Test
	public void testEditFunctionLabel() throws Exception {
		Function function = getTestFunction();

		int transactionID = notepad.startTransaction("test");
		try {
			function.setName("joe", SourceType.ANALYSIS);// in the global namespace
		}
		finally {
			notepad.endTransaction(transactionID, true);
		}
		// add a label
		AddLabelCmd cmd = new AddLabelCmd(addr(0x0), "fred", SourceType.USER_DEFINED);
		execute(cmd);

		// attempt to make joe primary, which is already primary -- should do nothing
		SetLabelPrimaryCmd c =
			new SetLabelPrimaryCmd(function.getEntryPoint(), "joe", function.getParentNamespace());
		assertTrue(execute(c));

		// make fred primary
		assertTrue(execute(new SetLabelPrimaryCmd(function.getEntryPoint(), "fred",
			function.getParentNamespace())));
		assertEquals("fred", function.getName());
		assertNotNull(getUniqueSymbol(notepad, "joe", null));
	}

	@Test
	public void testEditFunctionLabelInFunction() throws Exception {
		// add a label at a function and put the label in the function's namespace
		// set this label to be primary.
		// The function name should be just the name in the global namespace.

		Function function = getTestFunction();
		int transactionID = notepad.startTransaction("test");
		try {
			function.setName("joe", SourceType.ANALYSIS);// in the global namespace
			notepad.getSymbolTable().createLabel(function.getEntryPoint(), "fred", function,
				SourceType.USER_DEFINED);
		}
		finally {
			notepad.endTransaction(transactionID, true);
		}

		// make joe::fred primary
		// should drop the joe namespace and just be "fred"

		assertTrue(execute(new SetLabelPrimaryCmd(function.getEntryPoint(), "fred", function)));
		assertEquals("fred", function.getName());
		Symbol symbol = function.getSymbol();
		assertTrue(symbol.isPrimary());
		assertEquals("fred", symbol.getName(true));

	}

	private String makeName(int length) {
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i < length; i++) {
			// 0x21 - 0x7e permitted
			char c = (char) (0x21 + (i % 0x5e));
			buf.append(c);
		}
		return buf.toString();
	}

	private Address addr(long offset) {
		return notepad.getMinAddress().getNewAddress(offset);
	}

	private void testAddLabel(Program p) {
		ProgramLocation loc = new AddressFieldLocation(notepad, addr(0x1005e05));

		String baseName = "MyLabel_";
		Address addr = loc.getAddress();
		AddLabelCmd cmd = new AddLabelCmd(addr, baseName + (1), false, SourceType.USER_DEFINED);
		execute(cmd);
		Symbol s = p.getSymbolTable().getPrimarySymbol(addr);
		assertTrue(s.isPrimary());
	}

	private Function getTestFunction() {
		FunctionManager fm = notepad.getFunctionManager();
		Function function = fm.getFunctionAt(addr(0x0));
		if (function == null) {
			execute(new CreateFunctionCmd(addr(0x0)));
			function = fm.getFunctionAt(addr(0x0));
		}
		return function;
	}

	private Symbol testAddLabel(Program p, Address addr, String labelName) {

		AddLabelCmd cmd = new AddLabelCmd(addr, labelName, false, SourceType.USER_DEFINED);
		execute(cmd);
		return p.getSymbolTable().getPrimarySymbol(addr);
	}

	private boolean execute(Command cmd) {
		int txId = notepad.startTransaction("Transaction");
		boolean result = cmd.applyTo(notepad);
		notepad.endTransaction(txId, true);
		return result;
	}
}
