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

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.framework.cmd.Command;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test for the {@link ghidra.app.cmd.label.CreateNamespacesCmd} class.
 *
 *
 * @since  Tracker Id 619
 */
public class CreateNamespacesCmdTest extends AbstractGenericTest {

	private Program program;

	/**
	 * Constructor that takes the name of the test to run.
	 *
	 */
	public CreateNamespacesCmdTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		program = builder.getProgram();
	}

	@Test
	public void testCreationOfNamespaces() throws Exception {

		Namespace globalNamespace = program.getGlobalNamespace();
		assertTrue("The global namespace does not exist.",
			globalNamespace.getName().equals("Global"));
		SymbolTable symbolTable = program.getSymbolTable();

		// 1
		// string starts with parent (global) name
		// no parent given
		String[] namespaces1 = new String[] { "Global", "child1", "child2" };
		String namespaceString1 = createNamespaceStringFromArray(namespaces1);

		Command command = new CreateNamespacesCmd(namespaceString1, SourceType.USER_DEFINED);
		boolean success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString1 + "\nMessage: " +
			command.getStatusMsg(), success);

		// make sure the namespaces were created
		verifyNamespacesCreated(globalNamespace, namespaces1, symbolTable);

		// 2
		// string starts with parent/global name
		// parent given
		command =
			new CreateNamespacesCmd(namespaceString1, globalNamespace, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString1 + "\nMessage: " +
			command.getStatusMsg(), success);

		// make sure the namespaces were created
		verifyNamespacesCreated(globalNamespace, namespaces1, symbolTable);

		// 3
		// string does not start with parent (global) name
		// no parent given
		String[] namespaces3 = new String[] { "myChild1", "myChild2" };
		String namespaceString3 = createNamespaceStringFromArray(namespaces3);

		command = new CreateNamespacesCmd(namespaceString3, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString3 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(globalNamespace, namespaces3, symbolTable);

		// 4
		// string does not start with parent (global) name
		// parent given
		command =
			new CreateNamespacesCmd(namespaceString3, globalNamespace, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString3 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(globalNamespace, namespaces3, symbolTable);

		// 5
		// single name (not parent)
		// no parent given
		String[] namespaces5 = new String[] { "singleNameChild" };
		String namespaceString5 = createNamespaceStringFromArray(namespaces5);

		command = new CreateNamespacesCmd(namespaceString5, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString5 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(globalNamespace, namespaces5, symbolTable);

		// 6
		// single name (not parent)
		// parent given
		command =
			new CreateNamespacesCmd(namespaceString5, globalNamespace, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString5 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(globalNamespace, namespaces5, symbolTable);

		// 7
		// test global start string with different namespace parent
		String[] namespaces7 = new String[] { "Global", "child", "anotherChild" };
		String namespaceString7 = createNamespaceStringFromArray(namespaces7);

		// get a namespace with which to test
		Namespace lowLevelNamespace =
			createNamespace("lowLevelNamespace1", globalNamespace, symbolTable);
		lowLevelNamespace = createNamespace("lowLevelNamespace2", lowLevelNamespace, symbolTable);

		command =
			new CreateNamespacesCmd(namespaceString7, lowLevelNamespace, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString7 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(globalNamespace, namespaces7, symbolTable);

		// make sure that there was no "global" or "child" string created
		// under the parent namespace that we provided
		assertNull(
			"A child namespace was created under a node that was not " +
				"the global namespace as was expected.",
			findMatchingChildNamespace("global", lowLevelNamespace, symbolTable));
		assertNull(
			"A child namespace was created under a node that was not " +
				"the global namespace as was expected.",
			findMatchingChildNamespace("child", lowLevelNamespace, symbolTable));

		// 8
		// Invalid formats
		String[] namespaces8 = new String[] { "invalid name" };
		String namespaceString8 = createNamespaceStringFromArray(namespaces8);

		command = new CreateNamespacesCmd(namespaceString8, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Created a namespace from an invalid name format: " + namespaceString8 +
			"\nMessage: " + command.getStatusMsg(), !success);

		// 9
		// Null name string, no parent
		try {
			command = new CreateNamespacesCmd(null, SourceType.USER_DEFINED);

			Assert.fail("Did not receive the expected NullPointerException.");
		}
		catch (NullPointerException npe) {
			// good, expected
		}

		// 10
		// Null name string, with parent
		try {
			command = new CreateNamespacesCmd(null, globalNamespace, SourceType.USER_DEFINED);

			Assert.fail("Did not receive the expected NullPointerException.");
		}
		catch (NullPointerException npe) {
			// good, expected
		}

		// 11
		// Null parent results in global namespace being used
		String[] namespaces11 = new String[] { "foo", "bar", "baz", "bah" };
		String namespaceString11 = createNamespaceStringFromArray(namespaces11);

		command = new CreateNamespacesCmd(namespaceString11, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString11 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(globalNamespace, namespaces11, symbolTable);

		// 12
		// test that a non-global parent works
		String[] namespaces12 = new String[] { "foobarbaz", "child", "anotherChild" };
		String namespaceString12 = createNamespaceStringFromArray(namespaces12);

		// get a namespace with which to test
		lowLevelNamespace = createNamespace("lowLevelNamespace1", globalNamespace, symbolTable);
		lowLevelNamespace = createNamespace("lowLevelNamespace2", lowLevelNamespace, symbolTable);

		command =
			new CreateNamespacesCmd(namespaceString12, lowLevelNamespace, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString12 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(lowLevelNamespace, namespaces12, symbolTable);

		// 14
		// test that a function parent works
		Function func1 = createFunction();

		command = new CreateNamespacesCmd(namespaceString12, func1, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString12 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(func1, namespaces12, symbolTable);

		// 15
		// test that a class parent works
		GhidraClass c = createClass(symbolTable);

		command = new CreateNamespacesCmd(namespaceString12, c, SourceType.USER_DEFINED);
		success = execute(command);
		assertTrue("Failed to create namespaces from string: " + namespaceString12 + "\nMessage: " +
			command.getStatusMsg(), success);

		verifyNamespacesCreated(c, namespaces12, symbolTable);
	}

	private GhidraClass createClass(SymbolTable symbolTable)
			throws DuplicateNameException, InvalidInputException {

		int txId = program.startTransaction("Transaction");
		try {
			GhidraClass c = symbolTable.createClass(program.getGlobalNamespace(), "class1",
				SourceType.USER_DEFINED);
			assertNotNull(c);
			return c;
		}
		finally {
			program.endTransaction(txId, true);
		}

	}

	private Function createFunction()
			throws DuplicateNameException, InvalidInputException, OverlappingFunctionException {

		int txId = program.startTransaction("Transaction");
		try {
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0);
			Function func1 = program.getFunctionManager().createFunction("func1", addr,
				new AddressSet(addr), SourceType.USER_DEFINED);
			assertNotNull(func1);
			return func1;
		}
		finally {
			program.endTransaction(txId, true);
		}

	}

	private void verifyNamespacesCreated(Namespace parentNamespace, String[] namespaceNames,
			SymbolTable symbolTable) {

		Namespace childNamespace = parentNamespace;

		// take into account the case in which the first namespace name is
		// that of the given parent
		int i = 0;
		if (namespaceNames[0].equals(parentNamespace.getName())) {
			i = 1;
		}

		for (; i < namespaceNames.length; i++) {
			childNamespace =
				findMatchingChildNamespace(namespaceNames[i], childNamespace, symbolTable);
			assertNotNull("A child namespace was not created: " + namespaceNames[i],
				childNamespace);
		}
	}

	private String createNamespaceStringFromArray(String[] namespaceNames) {
		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i < namespaceNames.length; i++) {
			buffer.append(namespaceNames[i]);
			if (i + 1 < namespaceNames.length) {
				buffer.append(Namespace.DELIMITER);
			}
		}

		return buffer.toString();
	}

	private Namespace findMatchingChildNamespace(String namespaceName, Namespace parentNamespace,
			SymbolTable symbolTable) {

		SymbolIterator it = symbolTable.getSymbols(parentNamespace);
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s.getSymbolType() == SymbolType.NAMESPACE) {
				if (namespaceName.equals(s.getName())) {
					return (Namespace) s.getObject();
				}
			}
		}

		return null;
	}

	private Namespace createNamespace(String namespaceName, Namespace parentNamespace,
			SymbolTable symbolTable) {

		int txId = program.startTransaction("Transaction");
		try {
			Namespace ns = symbolTable.createNameSpace(parentNamespace, namespaceName,
				SourceType.USER_DEFINED);
			return ns;
		}
		catch (Exception e) {
			return findMatchingChildNamespace(namespaceName, parentNamespace, symbolTable);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private boolean execute(Command cmd) {
		int txId = program.startTransaction("Transaction");
		boolean result = cmd.applyTo(program);
		program.endTransaction(txId, true);
		return result;
	}
}
