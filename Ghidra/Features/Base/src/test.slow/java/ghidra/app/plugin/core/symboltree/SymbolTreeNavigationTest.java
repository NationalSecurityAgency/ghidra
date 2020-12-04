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
package ghidra.app.plugin.core.symboltree;

import static org.junit.Assert.*;

import java.util.Arrays;

import javax.swing.tree.TreePath;

import org.junit.*;

import docking.widgets.tree.GTreeNode;
import ghidra.app.cmd.function.*;
import ghidra.app.cmd.label.*;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolTreeRootNode;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.VariableNameFieldLocation;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.TaskMonitor;

public class SymbolTreeNavigationTest extends AbstractProgramBasedTest {

	private SymbolTreeTestUtils util;

	private SymbolTreePlugin plugin;

	@Override
	protected Program getProgram() throws Exception {
		return SymbolTreeTestUtils.buildProgram();
	}

	@Before
	public void setUp() throws Exception {
		initialize();

		plugin = env.getPlugin(SymbolTreePlugin.class);
		util = new SymbolTreeTestUtils(plugin, program);
		util.showSymbolTree(false);
		util.setGoToNavigationSelected(true);
	}

	@Override
	@After
	public void tearDown() throws Exception {
		util.closeProgram();
		env.dispose();
	}

	@Test
	public void testNavigateFromListing_Label_InGlobal() {

		Address addr = addr("0x01004896");
		Symbol symbol = createGlobalLabel(addr);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(symbol);
	}

	@Test
	public void testNavigationFromListing_Label_InGlobal_InOrganizationNode() {

		String labelsPrefix = "LabelNamePrefix";
		create10000Labels(labelsPrefix);

		Address addr = addr("0x01004896");
		String nameLowInOrgNodes = labelsPrefix + "3700";
		Symbol symbol = createGlobalLabel(addr, nameLowInOrgNodes);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(symbol);
	}

	@Test
	public void testInsertNode_AfterNavigation_Label_InGlobal_InOrganizationNode() {

		String labelsPrefix = "LabelNamePrefix";
		create10000Labels(labelsPrefix);

		Address addr = addr("0x01004896");
		String nameLowInOrgNodes = labelsPrefix + "3700";
		Symbol firstSymbol = createGlobalLabel(addr, nameLowInOrgNodes);

		util.collapseTree();
		goTo(addr);
		assertSelectedNode(firstSymbol);

		// create a name next to the one above so it gets 'insert'ed into the same parent node
		nameLowInOrgNodes = labelsPrefix + "37000";
		addr = addr.add(1);
		Symbol newSymbol = createGlobalLabel(addr, nameLowInOrgNodes);
		goTo(addr);
		assertSelectedNode(newSymbol);
	}

	@Test
	public void testNavigateFromListing_Label_InNamespace() {
		Address addr = addr("0x01004896");
		Symbol symbol = createLabelInNamespace(addr);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(symbol);
	}

	@Test
	public void testNavigateFromListing_Label_InClass() {
		Address addr = addr("0x01004896");
		Symbol symbol = createLabelInClass(addr);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(symbol);
	}

	@Test
	public void testNavigateFromListing_Label_InFunction() {
		Address addr = addr("0x01002cff");
		Symbol symbol = createLabelInFunction(addr);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(symbol);
	}

	@Test
	public void testNavigationFromListing_LabelInFunction_InOrganizationNode() {

		String namePrefix = "FunctionNamePrefix";
		Address start = addr("0x0100100a");
		create100Functions(start, namePrefix);
		Address addr = start.add(1); // inside of a function we just created
		Symbol symbol = createLabelInFunction(addr);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(symbol);
	}

	@Test
	public void testNavigationFromListing_FunctionParameter_InOrganizationNode() throws Exception {

		String namePrefix = "FunctionNamePrefix";
		Address start = addr("0x0100100a");
		create100Functions(start, namePrefix);
		Address addr = start.add(1); // inside of a function we just created

		FunctionManager fm = program.getFunctionManager();
		Function function = fm.getFunctionContaining(addr);
		Parameter parameter = addParameterToFunctionAt(function, addr);

		util.collapseTree();
		assertNoSelectedNode();

		goToVariable(function, parameter);

		assertSelectedNode(parameter.getSymbol());
	}

	@Test
	public void testNavigateFromListing_Label_InClassInFunction() {
		Address addr = addr("0x01002cff");
		Function f = function(addr("0x01002cf5"));
		parentFunctionToClass(f);
		Symbol symbol = createLabelInFunction(addr);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(symbol);
	}

	// @Test
	// Note: we have no way (that I know of) from within the listing to trigger a search
	//       for an external function.
	public void testNavigateFromListing_Function_InImport() {
		Address addr = addr("0x01002cff");
		Symbol symbol = createExternalFunction(addr);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(symbol);
	}

	@Test
	public void testNavigateFromListing_Function_InGlobal() {
		Address addr = addr("0x01002cf5");
		Function f = function(addr);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(f.getSymbol());
	}

	@Test
	public void testNavigateFromListing_Function_Parameter() {
		Address addr = addr("0x01002cf5");
		Function f = function(addr);

		util.collapseTree();
		assertNoSelectedNode();

		Parameter parameter = f.getParameter(0);
		goToVariable(f, parameter);

		assertSelectedNode(parameter.getSymbol());
	}

	@Test
	public void testNavigateFromListing_Function_InNamespace() {
		Address addr = addr("0x01002cf5");
		Function ghidra = function(addr);
		parentFunctionToNamespace("TestNamespace", ghidra);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(ghidra.getSymbol());
	}

	@Test
	public void testNavigateFromListing_Function_InClass() {
		Address addr = addr("0x01002cf5");
		Function f = function(addr);
		parentFunctionToClass(f);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		assertSelectedNode(f.getSymbol());
	}

	@Test
	public void testNavigateFromListing_MultipleSymbolsAtAddress_DuplicateNames() {

		Address addr = addr("0x01004896");
		String name = "duplicateName";
		Symbol s1 = createLabelInNamespace(addr, name, "Namespace1");
		Symbol s2 = createLabelInNamespace(addr, name, "Namespace2");
		Symbol s3 = createLabelInNamespace(addr, name, "Namespace3");

		int row = 0;
		goToLabel(s1, row++);
		assertSelectedNode(s1);

		goToLabel(s2, row++);
		assertSelectedNode(s2);

		goToLabel(s3, row++);
		assertSelectedNode(s3);

		goToLabel(s2, --row);
		assertSelectedNode(s2);

		goToLabel(s1, --row);
		assertSelectedNode(s1);

	}

	@Test
	public void testRenameRemovesSymbolFromOrgNode() {
		// we had a bug where a rename would leave the node inside of an org node and create a 
		// new symbol node with the updated name

		String labelsPrefix = "LabelNamePrefix";
		create10000Labels(labelsPrefix); // ensure org nodes created

		Address addr = addr("0x01004896");
		String nameLowInOrgNodes = labelsPrefix + "3700_test";
		Symbol symbol = createGlobalLabel(addr, nameLowInOrgNodes);

		util.collapseTree();
		assertNoSelectedNode();

		goTo(addr);

		GTreeNode oldNode = assertSelectedNode(symbol);

		TreePath oldPath = oldNode.getTreePath();

		// convert to strings, as the rename will update the TreePath object
		String[] oldPathStrings = toString(oldPath);
		String newName = "Bob";

		rename(symbol, newName);

		assertNodeDoesNotExist(oldPathStrings);
		assertNodeExists(symbol);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private String[] toString(TreePath p) {
		Object[] path = p.getPath();
		String[] strings = new String[path.length];
		for (int i = 0; i < path.length; i++) {
			strings[i] = path[i].toString();
		}

		return strings;
	}

	private Parameter addParameterToFunctionAt(Function f, Address addr)
			throws InvalidInputException {
		DataType dt = new Integer16DataType();
		Parameter p = new ParameterImpl("testParam", dt, program);
		AddParameterCommand cmd = new AddParameterCommand(f, p, 0, SourceType.USER_DEFINED);
		applyCmd(cmd);
		Parameter newParameter = f.getParameter(0);
		return newParameter;
	}

	private void create10000Labels(String labelsPrefix) {

		int txId = program.startTransaction("Test Create Labels");
		boolean commit = true;
		try {

			Address start = program.getMemory().getMinAddress();
			Address addr = start;
			for (int i = 1; i < 10000; i++) {
				String name = labelsPrefix + i;

				AddLabelCmd cmd = new AddLabelCmd(addr, name, SourceType.USER_DEFINED);
				cmd.applyTo(program);
				addr = start.add(i);
			}

		}
		finally {
			program.endTransaction(txId, commit);
		}

		program.flushEvents();
		waitForSwing();
	}

	private void create100Functions(Address start, String labelsPrefix) {

		int txId = program.startTransaction("Test Create Labels");
		boolean commit = true;
		try {

			int size = 5;
			Address addr = start;
			for (int i = 1; i < 100; i++) {
				String name = labelsPrefix + i;

				AddressSetView body = new AddressSet(addr, addr.add(size));
				CreateFunctionCmd cmd =
					new CreateFunctionCmd(name, addr, body, SourceType.USER_DEFINED);
				cmd.applyTo(program);
				addr = addr.add(size + 1);
			}

		}
		finally {
			program.endTransaction(txId, commit);
		}

		program.flushEvents();
		waitForSwing();
	}

	private void goToVariable(Function f, Variable variable) {

		Address entry = f.getEntryPoint();
		VariableNameFieldLocation loc =
			new VariableNameFieldLocation(f.getProgram(), entry, variable, 0);
		ProgramLocationPluginEvent e = new ProgramLocationPluginEvent("Test", loc, program);
		tool.firePluginEvent(e);
		waitForSwing();
	}

	private void goToLabel(Symbol symbol, int row) {
		LabelFieldLocation loc = new LabelFieldLocation(symbol, row, 0);
		ProgramLocationPluginEvent e = new ProgramLocationPluginEvent("Test", loc, program);
		tool.firePluginEvent(e);
		waitForSwing();
	}

	private void assertNodeExists(Symbol symbol) {

		SymbolNode key = SymbolNode.createNode(symbol, program);
		SymbolTreeRootNode rootNode = util.getRootNode();
		GTreeNode node = rootNode.findSymbolTreeNode(key, true, TaskMonitor.DUMMY);
		assertNotNull("Could not find node: " + symbol.getName(true), node);
	}

	private void assertNodeDoesNotExist(String[] pathStrings) {
		GTreeNode node = SymbolTreeTestUtils.getNode(util.getTree(), pathStrings);
		assertNull("Node should not exist in tree: " + Arrays.toString(pathStrings), node);
	}

	private void rename(Symbol symbol, String newName) {

		String oldName = symbol.getName();
		RenameLabelCmd cmd =
			new RenameLabelCmd(symbol.getAddress(), oldName, newName, SourceType.USER_DEFINED);
		applyCmd(cmd);
		util.waitForTree();
	}

	private Symbol createGlobalLabel(Address addr) {

		return createGlobalLabel(addr, "GlobalLabel");
	}

	private Symbol createGlobalLabel(Address addr, String labelName) {

		AddLabelCmd cmd = new AddLabelCmd(addr, labelName, SourceType.USER_DEFINED);
		applyCmd(cmd);
		Symbol symbol = cmd.getSymbol();
		assertNotNull("Unable to create symbol at " + addr, symbol);
		return symbol;
	}

	private Symbol createLabelInNamespace(Address addr) {
		return createLabelInNamespace(addr, "LabelInNamespace", "TestNamespace");
	}

	private Symbol createLabelInNamespace(Address addr, String labelName, String namespaceName) {
		CreateNamespacesCmd nsCmd = new CreateNamespacesCmd(namespaceName, SourceType.USER_DEFINED);
		applyCmd(nsCmd);
		Namespace ns = nsCmd.getNamespace();

		AddLabelCmd lableCmd = new AddLabelCmd(addr, labelName, ns, SourceType.USER_DEFINED);
		applyCmd(lableCmd);
		Symbol symbol = lableCmd.getSymbol();
		assertNotNull("Unable to create symbol at " + addr, symbol);
		return symbol;
	}

	private Symbol createLabelInClass(Address addr) {

		GhidraClass newClass = createInProgram(p -> {
			SymbolTable symbolTable = p.getSymbolTable();
			GhidraClass clazz = symbolTable.createClass(null, "TestClass", SourceType.USER_DEFINED);
			return clazz;
		});

		AddLabelCmd lableCmd =
			new AddLabelCmd(addr, "LabelInClass", newClass, SourceType.USER_DEFINED);
		applyCmd(lableCmd);
		Symbol symbol = lableCmd.getSymbol();
		assertNotNull("Unable to create symbol in a class at " + addr, symbol);
		return symbol;
	}

	private Symbol createLabelInFunction(Address addr) {
		FunctionManager fm = program.getFunctionManager();
		Function function = fm.getFunctionContaining(addr);
		assertNotNull("No function containing address: " + addr, function);

		AddLabelCmd lableCmd =
			new AddLabelCmd(addr, "LabelInFunction", function, SourceType.USER_DEFINED);
		applyCmd(lableCmd);
		Symbol symbol = lableCmd.getSymbol();
		assertNotNull("Unable to create symbol in a class at " + addr, symbol);
		return symbol;
	}

	private Symbol createExternalFunction(Address addr) {

		CreateExternalFunctionCmd cmd = new CreateExternalFunctionCmd("TestLibrary",
			"TestExternalFunction", addr, SourceType.USER_DEFINED);
		applyCmd(cmd);
		Symbol externalSymbol = cmd.getExtSymbol();
		assertNotNull("Unable to create symbol in a class at " + addr, externalSymbol);
		return externalSymbol;
	}

	private void parentFunctionToClass(Function f) {

		GhidraClass newClass = createInProgram(p -> {
			SymbolTable symbolTable = p.getSymbolTable();
			GhidraClass clazz = symbolTable.createClass(null, "TestClass", SourceType.USER_DEFINED);
			return clazz;
		});

		modifyProgram(p -> {
			f.setParentNamespace(newClass);
		});
	}

	private void parentFunctionToNamespace(String name, Function f) {
		modifyProgram(p -> {
			SymbolTable st = p.getSymbolTable();
			Namespace ns = st.createNameSpace(null, name, SourceType.USER_DEFINED);
			f.setParentNamespace(ns);
		});
	}

	private GTreeNode assertSelectedNode(Symbol symbol) {
		util.waitForTree();
		GTreeNode node = util.getSelectedNode();
		assertNotNull("No node selected; expected '" + symbol + "'", node);
		assertEquals(symbol.getName(), node.getName());
		assertEquals(symbol, ((SymbolNode) node).getSymbol());
		return node;
	}

	private void assertNoSelectedNode() {
		util.waitForTree();
		GTreeNode node = util.getSelectedNode();
		assertNull("Found a selected node when there should be no selection", node);
	}

	public void applyCmd(Command cmd) throws RollbackException {
		boolean success = applyCmd(program, cmd);
		assertTrue("Command failed - " + cmd.getName() + "; status = " + cmd.getStatusMsg(),
			success);
	}
}
