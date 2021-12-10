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
package ghidra.app.plugin.core.label;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Window;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.CreateNamespacesCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.viewer.field.MnemonicFieldFactory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.*;

public class AddEditDialoglTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private Program program;
	private AddEditDialog dialog;
	private PluginTool tool;
	private LabelMgrPlugin plugin;
	private Namespace globalScope;
	private SymbolTable st;
	private JCheckBox entryCheckBox;
	private JCheckBox primaryCheckBox;
	private JCheckBox pinnedCheckBox;
	private JComboBox<?> namespacesComboBox;
	private List<?> recentLabels;
	private JComboBox<?> labelNameChoices;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();

		globalScope = program.getGlobalNamespace();
		st = program.getSymbolTable();

		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(LabelMgrPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		plugin = getPlugin(tool, LabelMgrPlugin.class);

		builder.dispose();

		dialog = getAddEditDialog();

		entryCheckBox = (JCheckBox) getInstanceField("entryPointCheckBox", dialog);
		primaryCheckBox = (JCheckBox) getInstanceField("primaryCheckBox", dialog);
		pinnedCheckBox = (JCheckBox) getInstanceField("pinnedCheckBox", dialog);
		namespacesComboBox = (JComboBox<?>) getInstanceField("namespaceChoices", dialog);
		recentLabels = (List<?>) getInstanceField("recentLabels", dialog);
		labelNameChoices = (JComboBox<?>) getInstanceField("labelNameChoices", dialog);
	}

	private AddEditDialog getAddEditDialog() {
		AtomicReference<AddEditDialog> ref = new AtomicReference<>();
		runSwing(() -> {
			ref.set(plugin.getAddEditDialog());
		});
		return ref.get();
	}

	@After
	public void tearDown() throws Exception {
		dialog.close();
		env.dispose();
	}

	@Test
	public void testAddLabelSetUp() {
		addLabel(addr(0x0100642a));
		assertEquals("Add Label at 0100642a", dialog.getTitle());
		assertEquals("", getText());
		assertTrue(!entryCheckBox.isSelected());

		Namespace scope = getScope();
		assertEquals(globalScope, scope);
		assertTrue(primaryCheckBox.isSelected());
		assertTrue(!primaryCheckBox.isEnabled());
		pressCancel();
	}

	@Test
	public void testLabelChangeOne() {
		addLabel(addr(0x0100642a));
		setText("printf");
		pressOk();

		Symbol s = getUniqueSymbol(program, "printf", null);
		assertNotNull(s);
		assertTrue(s.isGlobal());
		assertEquals(addr(0x100642a), s.getAddress());
	}

	@Test
	public void testDuplicateLabelForAdd() {
		addLabel(addr(0x0100642a));
		setText("printf");
		pressOk();

		addLabel(addr(0x0100642c));
		setText("printf");
		assertEquals(" ", dialog.getStatusText());
		pressOk();
		assertTrue(dialog.getStatusText().length() > 0);
		pressCancel();
	}

	@Test
	public void testSetEntryPoint() {
		addLabel(addr(0x0100642a));
		setText("printf");
		setCheckbox(entryCheckBox, true);
		pressOk();
		assertTrue(!dialog.isVisible());
		Symbol s = getUniqueSymbol(program, "printf", null);
		assertNotNull(s);
		assertTrue(s.isExternalEntryPoint());
	}

	@Test
	public void testSetPinned() {
		addLabel(addr(0x0100642a));
		setText("printf");
		setCheckbox(pinnedCheckBox, true);
		pressOk();
		assertTrue(!dialog.isVisible());
		Symbol s = getUniqueSymbol(program, "printf", null);
		assertNotNull(s);
		assertTrue(s.isPinned());

		editLabel(s);
		setCheckbox(pinnedCheckBox, false);
		pressOk();
		assertTrue(!s.isPinned());

	}

	@Test
	public void testEmptyLabel() {
		addLabel(addr(0x0100642a));
		pressOk();
		assertTrue(dialog.isVisible());
		assertTrue(dialog.getStatusText().length() > 0);

	}

	@Test
	public void testInitNamespaces() throws Exception {
		createEntryFunction();

		int transactionID = program.startTransaction("Test");

		Namespace scope1 = st.createNameSpace(null, "Namespace1", SourceType.USER_DEFINED);
		Namespace scope2 = st.createNameSpace(scope1, "Namespace2", SourceType.USER_DEFINED);
		Namespace scope3 = st.createNameSpace(scope2, "Namespace3", SourceType.USER_DEFINED);
		Namespace scope4 = st.createNameSpace(scope3, "Namespace4", SourceType.USER_DEFINED);

		Symbol s = getUniqueSymbol(program, "entry", null);
		Function f = program.getListing().getFunctionAt(s.getAddress());
		f.setParentNamespace(scope4);

		Address address = addr(0x10065a6);
		Symbol symbol = st.createLabel(address, "sybmol1", scope4, SourceType.USER_DEFINED);
		editLabel(symbol);

		JComboBox<?> namespaceChoices = (JComboBox<?>) getInstanceField("namespaceChoices", dialog);

		// get a list of all namespaces in order to compare with the values
		// from the combo box
		// the first item should always be the global namespace...
		assertEquals("The first item in the list of namespaces is not the global namespace",
			program.getGlobalNamespace(), getScope(0));

		assertEquals("The symbol's namespace was not put into the proper place in the list.",
			getScope(2), symbol.getParentNamespace());

		// ...then, each namespace should be a child of the following
		// namespace
		int itemCount = namespaceChoices.getItemCount();
		for (int i = 1; i < itemCount - 1; i++) {
			Namespace currentNamespace = getScope(i);
			Namespace nextNamespace = getScope(i + 1);
			Namespace actualParent = currentNamespace.getParentNamespace();

			assertTrue("The namespaces are not in order in the " +
				"namespaceChoices combo box.  Each item should be a child of " + "following item.",
				nextNamespace.equals(actualParent));
		}

		// finally, the last item should be parented on the global namespace
		Namespace currentNamespace = getScope(itemCount - 1);
		Namespace actualParent = currentNamespace.getParentNamespace();

		assertTrue(
			"The namespaces are not in order in the " +
				"namespaceChoices combo box.  Each item should be a child of " + "following item.",
			actualParent.equals(program.getGlobalNamespace()));

		program.endTransaction(transactionID, true);
	}

	@Test
	public void testSetScope() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		createEntryFunction();
		Address a = addr(0x100642a);
		addLabel(a);
		setText("printf");
		Namespace scope = st.getNamespace(a);
		setScope(scope);
		pressOk();
		s = getUniqueSymbol(program, "printf", scope);
		assertNotNull(s);
		assertTrue(!s.isGlobal());
		assertEquals(st.getNamespace(a), s.getParentNamespace());
	}

	@Test
	public void testSetPrimaryAtExistingLabel() {
		Symbol s = getUniqueSymbol(program, "entry", null);
		assertTrue(s.isPrimary());
		addLabel(s.getAddress());
		assertEquals("", getText());
		assertTrue(entryCheckBox.isSelected());
		assertTrue(entryCheckBox.isEnabled());
		assertTrue(!primaryCheckBox.isSelected());
		assertTrue(primaryCheckBox.isEnabled());
		setText("printf");

		setCheckbox(primaryCheckBox, true);
		pressOk();
		s = getUniqueSymbol(program, "entry", null);
		assertTrue(!s.isPrimary());
		s = getUniqueSymbol(program, "printf", null);
		assertTrue(s.isPrimary());

	}

	@Test
	public void testSetPrimaryAtExistingLabel2() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		createEntryFunction();

		addLabel(s.getAddress());
		assertEquals("", getText());
		assertTrue(entryCheckBox.isSelected());
		assertTrue(entryCheckBox.isEnabled());
		assertTrue(!primaryCheckBox.isSelected());
		assertTrue(primaryCheckBox.isEnabled());

	}

	@Test
	public void testRecentLabels() {
		addLabel(addr(0x100642a));
		setText("aaaa");
		assertEquals(0, recentLabels.size());
		pressOk();

		assertEquals(1, recentLabels.size());
		assertEquals("aaaa", recentLabels.get(0));

		addLabel(addr(0x100642a));
		assertEquals("", getText());
		//assertEquals("aaaa", getText());
		setText("bbbb");
		pressOk();

		assertEquals(2, recentLabels.size());
		assertEquals("bbbb", recentLabels.get(0));
		assertEquals("aaaa", recentLabels.get(1));

	}

	@Test
	public void testRecentLabelsLimit() {
		for (int i = 0; i < 12; i++) {
			addLabel(addr(0x100642a));
			setText("l" + i);
			pressOk();
		}

		assertEquals(10, recentLabels.size());
		assertEquals("l11", recentLabels.get(0));
		assertEquals("l2", recentLabels.get(9));

	}

	@Test
	public void testEditLabel() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		editLabel(s);

		assertEquals("entry", getText());
		Object selectedItem = namespacesComboBox.getSelectedItem();
		assertEquals(globalScope, ((AddEditDialog.NamespaceWrapper) selectedItem).getNamespace());
		assertTrue(entryCheckBox.isSelected());
		assertTrue(primaryCheckBox.isSelected());
		assertTrue(!primaryCheckBox.isEnabled());
		pressCancel();

	}

	@Test
	public void testRenameFunction() throws Exception {

		Symbol s = getUniqueSymbol(program, "entry", null);
		Function function = program.getFunctionManager().getFunctionAt(s.getAddress());
		if (function == null) {
			tool.execute(new CreateFunctionCmd(s.getAddress()), program);
			program.flushEvents();
			waitForSwing();
			function = program.getFunctionManager().getFunctionAt(s.getAddress());
			s = getUniqueSymbol(program, "entry", null);
		}
		// add another label at this address
		AddLabelCmd cmd = new AddLabelCmd(addr(0x01006420), "fred", SourceType.USER_DEFINED);
		tool.execute(cmd, program);

		// now attempt to rename the entry label
		editLabel(s);
		assertEquals("entry", getText());
		setText("bob");
		pressOk();
		program.flushEvents();
		waitForSwing();
		assertEquals("bob", function.getName());
		assertTrue(function.getSymbol().isPrimary());
	}

	@Test
	public void testSetPrimaryOnOtherLabel() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		Function function = program.getFunctionManager().getFunctionAt(s.getAddress());
		if (function == null) {
			tool.execute(new CreateFunctionCmd(s.getAddress()), program);
			program.flushEvents();
			waitForSwing();
			function = program.getFunctionManager().getFunctionAt(s.getAddress());
		}
		// add another label at this address
		AddLabelCmd cmd = new AddLabelCmd(addr(0x01006420), "fred", SourceType.USER_DEFINED);
		tool.execute(cmd, program);

		Symbol fredSymbol = getUniqueSymbol(program, "fred", null);
		assertTrue(!fredSymbol.isPrimary());

		editLabel(fredSymbol);
		setCheckbox(primaryCheckBox, true);
		pressOk();
		program.flushEvents();
		waitForSwing();
		assertEquals("fred", function.getName());
		assertNotNull(getUniqueSymbol(program, "entry", null));
	}

	@Test
	public void testSelectedNamespace() throws Exception {

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol s = getUniqueSymbol(program, "rsrc_String_6_64", null);

		int transactionID = program.startTransaction("test");
		Namespace ns = symbolTable.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		s.setNamespace(ns);
		program.endTransaction(transactionID, true);

		editLabel(s);

		Object selectedItem = namespacesComboBox.getSelectedItem();
		assertEquals(ns, ((AddEditDialog.NamespaceWrapper) selectedItem).getNamespace());
		pressCancel();

	}

	@Test
	public void testEditDefaultLabel() {
		Address refAddr = addr(0x10064b1);
		Symbol s = st.getPrimarySymbol(refAddr);
		editLabel(s);
		assertEquals("LAB_010064b1", getText());
		assertTrue(!entryCheckBox.isSelected());
		assertTrue(primaryCheckBox.isSelected());
		assertTrue(!primaryCheckBox.isEnabled());
		setText("aaaa");
		pressOk();
		s = st.getPrimarySymbol(refAddr);
		assertEquals("aaaa", s.getName());
	}

	@Test
	public void testRenameLabel() {
		Symbol s = getUniqueSymbol(program, "entry", null);
		Address a = s.getAddress();
		editLabel(s);

		setText("fred");
		pressOk();
		assertEquals("fred", s.getName());

		s = st.getPrimarySymbol(a);
		assertEquals("fred", s.getName());

	}

	@Test
	public void testDuplicateLabelForEdit() {
		addLabel(addr(0x100642a));
		setText("printf");
		pressOk();

		addLabel(addr(0x100642a));
		setText("fred");
		pressOk();

		Symbol s = getUniqueSymbol(program, "printf", null);
		editLabel(s);

		setText("fred");
		pressOk();
		assertTrue(dialog.isVisible());
		assertTrue(dialog.getStatusText().length() > 0);

	}

	@Test
	public void testRenameOneLabel() {
		Address a = addr(0x100642a);
		addLabel(a);
		setText("aaaa");
		pressOk();
		addLabel(a);
		setText("bbbb");
		pressOk();
		addLabel(a);
		setText("cccc");
		pressOk();

		Symbol s = getUniqueSymbol(program, "bbbb", null);
		editLabel(s);
		setText("zzzz");
		pressOk();
		assertNotNull(getUniqueSymbol(program, "aaaa", null));
		assertNotNull(getUniqueSymbol(program, "zzzz", null));
		assertNotNull(getUniqueSymbol(program, "cccc", null));
		assertNull(getUniqueSymbol(program, "bbbb", null));
	}

	@Test
	public void testEdit() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		assertTrue(s.isGlobal());
		Address a = s.getAddress();
		createEntryFunction();
		s = getUniqueSymbol(program, "entry", null);
		assertTrue(s.isGlobal());
		addLabel(s.getAddress());
		setScope(st.getNamespace(a));
		assertTrue(!primaryCheckBox.isSelected());
		assertTrue(primaryCheckBox.isEnabled());
		setText("foo");
		pressOk();

		s = st.getPrimarySymbol(a);
		assertNotNull(s);
		assertTrue(s.isGlobal());
		assertTrue(s.isPrimary());
		s = getUniqueSymbol(program, "foo", st.getNamespace(a));
		assertNotNull(s);
		assertEquals("entry", s.getParentNamespace().getName());
	}

	@Test
	public void testEdit_CannotRemoveDefaultLabel() {

		Address refAddr = addr(0x10064b1);
		Symbol s = st.getPrimarySymbol(refAddr);
		editLabel(s);
		assertEquals("LAB_010064b1", getText());

		setText("");

		pressOk();

		assertStatusText("Name cannot be blank");
	}

	@Test
	public void testEdit_RemoveNonDefaultLabel() {

		Address a = addr(0x100642a);
		addLabel(a);
		String labelName = "aaaa";
		setText(labelName);
		pressOk();

		Symbol s = st.getPrimarySymbol(a);
		editLabel(s);
		assertEquals(labelName, getText());

		setText("");
		pressOk();

		Window w = waitForWindow("Remove Label?");
		pressButtonByText(w, "Yes");
		assertEditDialogVisible(false);

		assertNull(getUniqueSymbol(program, labelName, null));
	}

	@Test
	public void testRecentLabelsForEdit() {
		Symbol s = getUniqueSymbol(program, "entry", null);

		addLabel(s.getAddress());
		setText("aaaa");
		pressOk();

		s = getUniqueSymbol(program, "aaaa", null);
		editLabel(s);
		setText("zzzz");
		pressOk();

		editLabel(s);
		setText("bbbb");
		pressOk();

		assertEquals(3, recentLabels.size());
		assertEquals("bbbb", recentLabels.get(0));
	}

	@Test
	public void testPrimaryEnablement() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);

		createEntryFunction();
		addLabel(s.getAddress());
		setScope(s.getParentNamespace());
		setText("foo");
		pressOk();

		s = getUniqueSymbol(program, "foo", null);
		editLabel(s);
		assertTrue(primaryCheckBox.isEnabled());
		assertTrue(!primaryCheckBox.isSelected());
		pressOk();
	}

	@Test
	public void testPrimaryEnablement2() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		// add another label at this address
		AddLabelCmd cmd = new AddLabelCmd(s.getAddress(), "fred", SourceType.USER_DEFINED);
		tool.execute(cmd, program);
		program.flushEvents();
		waitForSwing();

		editLabel(s);

		assertTrue(!primaryCheckBox.isEnabled());
		assertTrue(primaryCheckBox.isSelected());
	}

	@Test
	public void testPrimaryEnablement3() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		editLabel(s);

		assertTrue(!primaryCheckBox.isEnabled());
		assertTrue(primaryCheckBox.isSelected());
	}

	/**
	 * Catches the issue where the user could not move a label within a
	 * namespace under the Global namespace to directly under the Global
	 * namespace.
	 *
	 * see Tracker ID 901
	 */
	@Test
	public void testMoveCurrentLabelToGlobalNamespace() {
		Symbol s = getUniqueSymbol(program, "entry", null);

		Address entryAddress = s.getAddress();
		addLabel(entryAddress);
		setText("label_1");
		pressOk();

		assertTrue("Encountered a problem adding a label to the Global namespace",
			!dialog.isVisible());

		// move the label to a new namespace
		s = getUniqueSymbol(program, "label_1", null);
		editLabel(s);
		setText("namespace_1::label_1");
		pressOk();

		// make sure there were no problems
		assertTrue(
			"Encountered a problem changing a symbol's namespace while editing the symbol",
			!dialog.isVisible());

		// now move that label to the Global namespace
		s = st.getSymbols("label_1").next();
		editLabel(s);
		setText("Global::label_1");
		pressOk();

		assertTrue("Encountered a problem changing a symbol's namespace to " +
			"the Global namespace while editing the symbol", !dialog.isVisible());
	}

	@Test
	public void testSetLabelNamespace_InsideFunctionBody_ToFunctionNamespace() {
		Symbol entry = getUniqueSymbol(program, "entry", null);
		assertNotNull(entry);

		Address inBodyAddress = entry.getAddress().add(1);
		addLabel(inBodyAddress);
		String newName = "label_1";
		setText("entry" + Namespace.DELIMITER + newName);
		pressOk();
		assertFalse("Encountered a problem adding a label to the Global namespace",
			dialog.isVisible());

		Symbol label1 = getSymbol(newName);
		Namespace parentNamespace = label1.getParentNamespace();
		assertTrue("Namespace is not a function", parentNamespace instanceof Function);
		Function fun = (Function) parentNamespace;
		assertEquals(entry.getAddress(), fun.getEntryPoint());
	}

	@Test
	public void testSetLabelNamespace_InsideFunctionBody_ToExistingNonFunctionNamespace() {

		Symbol entry = getUniqueSymbol(program, "entry", null);
		assertNotNull(entry);

		String namespaceName = "NewNamespace";
		createNamespace(namespaceName);

		Address inBodyAddress = entry.getAddress().add(1);
		addLabel(inBodyAddress);
		String newName = "label_1";
		setText(namespaceName + Namespace.DELIMITER + newName);
		pressOk();
		assertFalse("Encountered a problem adding a label to the Global namespace",
			dialog.isVisible());

		Symbol label1 = getSymbol(newName);
		Namespace parentNamespace = label1.getParentNamespace();
		assertFalse("Namespace is not a function", parentNamespace instanceof Function);
	}

	@Test
	public void testSetLabelNamespace_InsideFunctionBody_ToNonExistentNonFunctionNamespace() {

		Symbol entry = getUniqueSymbol(program, "entry", null);
		assertNotNull(entry);

		String namespaceName = "NewNamespace";
		Address inBodyAddress = entry.getAddress().add(1);
		addLabel(inBodyAddress);
		String newName = "label_1";
		setText(namespaceName + Namespace.DELIMITER + newName);
		pressOk();
		assertFalse("Encountered a problem adding a label to the Global namespace",
			dialog.isVisible());

		Symbol label1 = getSymbol(newName);
		Namespace parentNamespace = label1.getParentNamespace();
		assertFalse("Namespace is not a function", parentNamespace instanceof Function);
	}

	@Test
	public void testEntryNamespacePathWithAmbiguousFunctionName() {
		Symbol entry = getUniqueSymbol(program, "entry", null);
		assertNotNull(entry);

		Address otherEntryAddress = addr(0x1002239);
		Symbol dupEntry = createOtherEntry(otherEntryAddress);

		Address inBodyAddress = otherEntryAddress.add(1);
		addLabel(inBodyAddress);
		String newName = "label_1";
		setText("entry" + Namespace.DELIMITER + newName);
		pressOk();
		assertFalse("Encountered a problem adding a label to the Global namespace",
			dialog.isVisible());

		Symbol label1 = getSymbol(newName);
		Namespace parentNamespace = label1.getParentNamespace();
		assertTrue("Namespace is not a function", parentNamespace instanceof Function);
		Function fun = (Function) parentNamespace;
		assertEquals(dupEntry.getAddress(), fun.getEntryPoint());
	}

	@Test
	public void testSetNamespace_NonExistentNamespace_SameNameAsFunction() throws Exception {

		//
		// Test that we can create a new namespace using the dialog when:
		// 1) that namespace does not exist
		// 2) the namespace matches the existing function name
		// 3) the function name is not default
		//

		String functionName = "Foo";
		Symbol function = createFunction(functionName);

		editLabel(function);
		String nsName = functionName;
		setText(nsName + Namespace.DELIMITER + functionName);
		pressOk();
		assertFalse("Rename unsuccesful", dialog.isShowing());

		Symbol newFunction = getSymbol(functionName);
		Namespace parentNs = newFunction.getParentNamespace();
		assertFalse(parentNs instanceof Function);
		assertEquals(nsName, parentNs.getName());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertStatusText(String expected) {
		assertEquals("Dialog status text not as expected", expected,
			runSwing(dialog::getStatusText));
	}

	private void assertEditDialogVisible(boolean visible) {
		assertEquals("Dialog " + (visible ? "not showing" : "showing") +
			"when it should be " + (visible ? "showing" : "not showing"), visible,
			runSwing(dialog::isShowing));
	}

	private Symbol createOtherEntry(Address otherAddress) {
		Symbol dupEntry = st.getPrimarySymbol(otherAddress);
		assertNotNull(dupEntry);

		int id = program.startTransaction("test");
		try {
			dupEntry.setName("entry", SourceType.USER_DEFINED);
		}
		catch (Exception e) {
			fail("Got Exception trying to set the function name to entry at " + otherAddress);
		}
		finally {
			program.endTransaction(id, true);
		}
		return dupEntry;
	}

	private Symbol getSymbol(String functionName) {

		SymbolIterator it = st.getSymbols(functionName);
		Symbol newLabel = it.next();
		assertNotNull(newLabel);
		assertEquals(functionName, newLabel.getName());
		return newLabel;
	}

	private Symbol createFunction(String name) throws Exception {
		Symbol entry = getUniqueSymbol(program, "entry", null);
		createEntryFunction();
		editLabel(entry);
		setText(name);
		pressOk();

		SymbolIterator it = st.getSymbols(name);
		Symbol newLabel = it.next();
		assertNotNull(newLabel);
		assertEquals(name, newLabel.getName());
		return newLabel;
	}

	private Address addr(long addr) {
		return program.getAddressFactory().getAddress(Long.toHexString(addr));
	}

	private void pressCancel() {
		runSwing(() -> invokeInstanceMethod("cancelCallback", dialog));
	}

	private void pressOk() {
		runSwing(() -> invokeInstanceMethod("okCallback", dialog), false);
		waitForSwing();
	}

	private void setText(final String text) {
		runSwing(() -> {
			Component comp = labelNameChoices.getEditor().getEditorComponent();
			((JTextField) comp).setText(text);
		}, false);
	}

	private String getText() {
		Component comp = labelNameChoices.getEditor().getEditorComponent();
		return ((JTextField) comp).getText();
	}

	private void setCheckbox(final JCheckBox checkbox, final boolean value) {
		runSwing(() -> checkbox.setSelected(value));
	}

	private Namespace getScope() {
		final AtomicReference<Namespace> ref = new AtomicReference<>();
		runSwing(() -> {
			Object selectedItem = namespacesComboBox.getSelectedItem();
			Namespace ns = ((AddEditDialog.NamespaceWrapper) selectedItem).getNamespace();
			ref.set(ns);
		});
		return ref.get();
	}

	private Namespace getScope(final int index) {
		final AtomicReference<Namespace> ref = new AtomicReference<>();
		runSwing(() -> {
			int count = namespacesComboBox.getItemCount();
			if (count <= index) {
				System.err.println("Available namespaces: ");
				for (int i = 0; i < count; i++) {
					System.err.println("\t" + namespacesComboBox.getItemAt(i));
				}
				throw new IllegalArgumentException("No namespace at index: " + index);
			}

			Object selectedItem = namespacesComboBox.getItemAt(index);
			Namespace ns = ((AddEditDialog.NamespaceWrapper) selectedItem).getNamespace();
			ref.set(ns);
		});
		return ref.get();
	}

	private void setScope(final Namespace scope) {
		runSwing(() -> namespacesComboBox.setSelectedItem(dialog.new NamespaceWrapper(scope)));
	}

	private void addLabel(final Address addr) {

		// this makes debugging easier
		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		cb.goToField(addr, MnemonicFieldFactory.FIELD_NAME, 0, 0);

		runSwing(() -> dialog.addLabel(addr, program), false);
		waitForSwing();

		setScope(globalScope);
	}

	private void editLabel(final Symbol symbol) {
		// this makes debugging easier
		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		cb.goToField(symbol.getAddress(), MnemonicFieldFactory.FIELD_NAME, 0, 0);

		runSwing(() -> dialog.editLabel(symbol, program), false);
		waitForSwing();
	}

	private void createEntryFunction() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		Function f = program.getListing().getFunctionAt(s.getAddress());
		if (f == null) {
			Address addr = s.getAddress();
			AddressSet body = new AddressSet(addr, addr.getNewAddress(0x010065cc));
			body.addRange(addr.getNewAddress(0x10065a4), addr.getNewAddress(0x010065cc));
			CreateFunctionCmd cmd =
				new CreateFunctionCmd(null, addr, body, SourceType.USER_DEFINED);
			assertTrue(tool.execute(cmd, program));
		}
	}

	private void createNamespace(String name) {
		applyCmd(program, new CreateNamespacesCmd(name, SourceType.USER_DEFINED));
	}
}
