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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.FocusListener;
import java.awt.event.KeyEvent;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.DockingDialog;
import docking.action.DockingActionIf;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.util.DataTypeChooserDialog;
import ghidra.app.plugin.core.stackeditor.StackFrameDataType;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.Composite.AlignmentType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;

public abstract class AbstractEditorTest extends AbstractGhidraHeadedIntegrationTest {
	protected String languageName;
	protected String compilerSpecID;
	protected CompositeEditorProvider provider;
	protected CompositeEditorModel model;
	protected TestEnv env;
	protected ProgramBuilder builder;
	protected Program program;
	protected PluginTool tool;
	protected DataTypeManagerPlugin plugin;
	protected DataTypeManager programDTM;
	protected Category pgmRootCat;
	protected Category pgmTestCat;
	protected Category pgmAaCat;
	protected Category pgmBbCat;
	protected Structure emptyStructure;
	protected Union emptyUnion;
	protected Structure simpleStructure;
	protected Union simpleUnion;
	protected Structure complexStructure;
	protected Union complexUnion;
	protected DataTypeManagerService dtmService;
	protected PointerDataType POINTER;
	protected int txId;
	protected StatusListener listener;

	protected CompositeEditorAction[] actions;
	protected ArrayList<FavoritesAction> favorites = new ArrayList<>();
	protected ArrayList<CycleGroupAction> cycles = new ArrayList<>();

	/**
	 * Constructor for an EditorTest.
	 * @param name the test case name.
	 */
	protected AbstractEditorTest() {
		POINTER = new PointerDataType();
		languageName = ProgramBuilder._TOY;
		compilerSpecID = "default";
	}

	@Before
	public void setUp() throws Exception {
		fixupGUI();
		env = new TestEnv();
		tool = env.showTool();
		setUpPlugins();

		builder = new ProgramBuilder("Test", languageName, compilerSpecID, this);
		program = builder.getProgram();
		env.open(program);
		dtmService = tool.getService(DataTypeManagerService.class);
		assertNotNull(dtmService);

		runSwing(() -> {
			CommonTestData.initialize();
			emptyStructure = CommonTestData.emptyStructure;
			emptyUnion = CommonTestData.emptyUnion;
			boolean commit = false;
			txId = program.startTransaction("Modify Program");
			try {
				programDTM = program.getListing().getDataTypeManager();
				pgmRootCat = programDTM.getRootCategory();
				programDTM.createCategory(CommonTestData.category.getCategoryPath());
				pgmTestCat = programDTM.createCategory(CommonTestData.category.getCategoryPath());
				pgmAaCat = programDTM.createCategory(CommonTestData.aaCategory.getCategoryPath());
				pgmBbCat = programDTM.createCategory(CommonTestData.bbCategory.getCategoryPath());
				simpleStructure =
					(Structure) programDTM.resolve(CommonTestData.simpleStructure, null);
				simpleUnion = (Union) programDTM.resolve(CommonTestData.simpleUnion, null);
				complexStructure =
					(Structure) programDTM.resolve(CommonTestData.complexStructure, null);
				complexUnion = (Union) programDTM.resolve(CommonTestData.complexUnion, null);
				commit = true;
			}
			finally {
				program.endTransaction(txId, commit);
			}
			listener = new StatusListener();
		});
	}

	protected void installProvider(CompositeEditorProvider newProvider) {
		assertNotNull(newProvider);
		this.provider = newProvider;
		runSwing(() -> removeTableCellEditorsFocusLostListener());
	}

	/**
	 * Adds all plugins required for this test.
	 */
	protected void setUpPlugins() throws Exception {
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		assertNotNull(plugin);
	}

	@After
	public void tearDown() throws Exception {

		// stop any editing now before later dispose in order to avoid exceptions due to
		// invokeLater()
		runSwing(() -> {
			if (model != null) {
				model.endEditingField();
			}
		});

		closeAllWindowsAndFrames();

		// this is an attempt to prevent stack traces when take down the environment out from
		// under Swing

		if (model != null) {
			model = null;
		}

		// run on Swing thread due to action removal
		runSwing(() -> {
			if (provider != null) {
				provider.dispose();
				provider = null;
			}
		});

		waitForSwing();

		listener = null;
		CommonTestData.cleanUp();
		env.dispose();
	}

	String getProviderSubTitle(Composite compositeDataType) {
		String dtmName;
		DataTypeManager dtm = compositeDataType.getDataTypeManager();
		if (dtm == null) {
			return compositeDataType.getDisplayName();
		}
		if (dtm instanceof ProgramBasedDataTypeManager) {
			ProgramBasedDataTypeManager programDtm = (ProgramBasedDataTypeManager) dtm;
			dtmName = programDtm.getProgram().getDomainFile().getName();
		}
		else {
			dtmName = dtm.getName();
		}
		return compositeDataType.getDisplayName() + " (" + dtmName + ")";
	}

	@SuppressWarnings("unused")
	private String getName(Composite composite) {
		if (composite instanceof Structure) {
			return "Structure Editor";
		}
		else if (composite instanceof Union) {
			return "Union Editor";
		}
		else if (composite instanceof Enum) {
			return "Enum Editor";
		}
		else if (composite instanceof StackFrameDataType) {
			return "Stack Editor";
		}
		else {
			return "Composite Data Type Editor";
		}
	}

	protected CycleGroupAction getCycleGroup(DataType dt) {
		for (int cycleIndex = 0; cycleIndex < cycles.size(); cycleIndex++) {
			CycleGroupAction action = cycles.get(cycleIndex);
			CycleGroup group = action.getCycleGroup();
			DataType[] types = group.getDataTypes();
			for (DataType type : types) {
				if (type.isEquivalent(dt)) {
					return action;
				}
			}
		}
		return null;
	}

	protected FavoritesAction getFavorite(String name) {
		for (int favIndex = 0; favIndex < favorites.size(); favIndex++) {
			FavoritesAction action = favorites.get(favIndex);
			if (action.getDataType().getDisplayName().equals(name)) {
				return action;
			}
		}
		Assert.fail("Can't find favorite " + name + ".");
		return null;
	}

	/**
	 *  Creates a selection on the indicated indices.
	 *
	 * @param indices the indices for the selection.
	 */
	protected FieldSelection createSelection(int[] indices) {
		FieldSelection selection = new FieldSelection();
		for (int indice : indices) {
			selection.addRange(indice, indice + 1);
		}
		return selection;
	}

	/**
	 * @param rows the rows in ascending order that are expected to make up the current selection.
	 */
	protected void checkSelection(int[] rows) {
		int[] tRows = getTable().getSelectedRows();
		if (!Arrays.equals(rows, tRows)) {
			Assert.fail("Expected row selection (" + arrayToString(rows) + ") but was (" +
				arrayToString(tRows) + ").");
		}
		assertEquals(createSelection(rows), model.getSelection());
	}

	/**
	 * Set the table selection to the indicated rows.
	 * @param rows the rows in ascending order that are expected to make up the current selection.
	 */
	protected void setSelection(final int[] rows) {
		runSwing(() -> {
			FieldSelection fs = createSelection(rows);
			ListSelectionModel lsm = getTable().getSelectionModel();
			lsm.clearSelection();
			int num = fs.getNumRanges();
			for (int i = 0; i < num; i++) {
				FieldRange range = fs.getFieldRange(i);
				lsm.addSelectionInterval(range.getStart().getIndex().intValue(),
					range.getEnd().getIndex().intValue() - 1);
			}
		});
	}

	private String arrayToString(int[] values) {
		StringBuffer buf = new StringBuffer();
		for (int value : values) {
			buf.append(Integer.toString(value) + ", ");
		}
		if (values.length > 0) {
			int len = buf.length();
			buf.replace(len - 2, len, "");
		}
		return buf.toString();
	}

	// presses enter and selects a match from the resulting dialog in the case where multiple
	// matches exist
	protected void pressEnterToSelectChoice() {
		triggerActionInCellEditor(KeyEvent.VK_ENTER);
		waitForSwing();
		checkForMultipleMatches();
	}

	// checks for a dialog showing multiple matching names and selects the first one if the
	// dialog is found
	protected void checkForMultipleMatches() {
		waitForSwing();
		Window window = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusedWindow();
		if (window instanceof DockingDialog) {
			Object componentProvider = getInstanceField("component", window);
			if (componentProvider instanceof DataTypeChooserDialog) {
				// we must make a selection
				Object treePanel = getInstanceField("treePanel", componentProvider);
				final JTree tree = (JTree) getInstanceField("tree", treePanel);
				DefaultMutableTreeNode root = (DefaultMutableTreeNode) tree.getModel().getRoot();
				DefaultMutableTreeNode matchingNode = findFirstLeafNode(root);
				TreePath treePath = (TreePath) invokeInstanceMethod("getTreePath", matchingNode);
				tree.setSelectionPath(treePath);
				JButton okButton = (JButton) getInstanceField("okButton", componentProvider);
				pressButton(okButton);
			}
		}
	}

	private DefaultMutableTreeNode findFirstLeafNode(DefaultMutableTreeNode node) {
		if (node.isLeaf()) {
			return node;
		}

		int childCount = node.getChildCount();
		for (int i = 0; i < childCount; i++) {
			DefaultMutableTreeNode matchingNode =
				findFirstLeafNode((DefaultMutableTreeNode) node.getChildAt(i));
			if (matchingNode != null) {
				return matchingNode;
			}
		}

		return null;
	}

	protected void invoke(final DockingActionIf action) {
		assertNotNull(action);
		boolean isEnabled = runSwing(() -> action.isEnabled());
		if (!isEnabled) {
			Msg.debug(this, "Calling actionPerformed() on a disabled action: " + action.getName());
		}
		runSwing(() -> action.actionPerformed(new ActionContext()), false);
		waitForSwing();
	}

	protected void badInput(NumberInputDialog dialog, int input) {

		runSwing(() -> dialog.setInput(input));
		waitForSwing();
		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		assertTrue("Expected OkButton to be disabled", !okButton.isEnabled());
	}

	protected void okInput(NumberInputDialog dialog, int input) {

		runSwing(() -> dialog.setInput(input));
		waitForSwing();
		pressButtonByText(dialog, "OK");
		waitForSwing();
	}

	protected void cancelInput(NumberInputDialog numInputDialogComponent) throws Exception {
		pressButtonByText(numInputDialogComponent, "Cancel");
	}

	protected void waitUntilDialogProviderGone(Class<NumberInputDialog> clazz, int applyMS) {

		waitForCondition(() -> getDialogComponent(clazz) == null,
			"Failed waiting for " + clazz.getName() + " to be closed");
	}

	protected void pressButton(Container container, String buttonText) {
		pressButtonByText(container, buttonText);
	}

	protected void pressButton(final JButton button) {
		executeOnSwingWithoutBlocking(() -> button.doClick());
	}

	protected int getOffset(int index) {
		DataTypeComponent dtc = model.getComponent(index);
		return (dtc != null) ? dtc.getOffset() : -1;
	}

	protected int getLength(int index) {
		DataTypeComponent dtc = model.getComponent(index);
		return (dtc != null) ? dtc.getLength() : -1;
	}

	protected DataType getDataType(int index) {
		DataTypeComponent dtc = model.getComponent(index);
		return (dtc != null) ? dtc.getDataType() : null;
	}

	protected String getFieldName(int index) {
		DataTypeComponent dtc = model.getComponent(index);
		return (dtc != null) ? dtc.getFieldName() : null;
	}

	protected String getComment(int index) {
		DataTypeComponent dtc = model.getComponent(index);
		return (dtc != null) ? dtc.getComment() : null;
	}

	protected CompositeEditorPanel getPanel() {
		return (CompositeEditorPanel) provider.getComponent();
	}

	protected JTable getTable() {
		return ((CompositeEditorPanel) provider.getComponent()).table;
	}

	protected Window getWindow() {
		Component comp = provider.getComponent();
		while (comp != null && !(comp instanceof Window)) {
			comp = comp.getParent();
		}
		return (Window) comp;
	}

	/**
	 * Gets the point for the center of the table cell at the indicated row and column.
	 * @param row the table cell row
	 * @param column the table cell column
	 * @return the center point
	 */
	protected Point getPoint(int row, int column) {
		JTable table = getTable();
		Rectangle rect = table.getCellRect(row, column, true);
		return new Point(rect.x + (rect.width / 2), rect.y + (rect.height / 2));
	}

	protected void addAtPoint(DataType dt, int row, int col) {
		runSwing(() -> getPanel().addAtPoint(getPoint(row, col), dt), false);
		waitForSwing();
	}

	protected void insertAtPoint(DataType dt, int row, int col) {
		runSwing(() -> getPanel().insertAtPoint(getPoint(row, col), dt), false);
		waitForSwing();
	}

	/**
	 * Types the indicated string
	 * 
	 * <br>Note: Handles upper and lowercase alphabetic characters,
	 * numeric characters, and other standard keyboard characters that are
	 * printable characters. It also handles '\n', '\t', and '\b'.
	 * @param str
	 */
	protected void type(String str) {
		triggerText(getActiveEditorTextField(), str);
	}

	protected void enter() {
		triggerActionKey(getKeyEventDestination(), 0, KeyEvent.VK_ENTER);
		waitForSwing();
	}

	protected void escape() {
		triggerActionKey(getKeyEventDestination(), 0, KeyEvent.VK_ESCAPE);
		waitForSwing();
	}

	protected void ok() {
		// no-op?
	}

	protected void backspace(int repeat) {
		for (int i = 0; i < repeat; i++) {
			triggerActionKey(getTable(), 0, KeyEvent.VK_BACK_SPACE);
		}
		waitForSwing();
	}

	protected void leftArrowKey(int repeat) {
		for (int i = 0; i < repeat; i++) {
			triggerActionKey(getTable(), 0, KeyEvent.VK_LEFT);
		}
		waitForSwing();
	}

	protected void rightArrowKey(int repeat) {
		for (int i = 0; i < repeat; i++) {
			triggerActionKey(getTable(), 0, KeyEvent.VK_RIGHT);
		}
		waitForSwing();
	}

	protected void endKey() {
		triggerActionKey(getKeyEventDestination(), 0, KeyEvent.VK_END);
		waitForSwing();
	}

	protected void startTransaction(final String txDescription) {
		runSwing(() -> {
			try {
				txId = program.startTransaction(txDescription);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});
	}

	protected void endTransaction(final boolean saveChanges) {
		runSwing(() -> {
			try {
				program.endTransaction(txId, saveChanges);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});
	}

	protected class RestoreListener implements DomainObjectListener {
		/**
		 * @see ghidra.framework.model.DomainObjectListener#domainObjectChanged(ghidra.framework.model.DomainObjectChangedEvent)
		 */
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent event) {
			if (event.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
				Object source = event.getSource();
				if (source instanceof DataTypeManagerDomainObject) {
					DataTypeManagerDomainObject restoredDomainObject =
						(DataTypeManagerDomainObject) source;
					provider.domainObjectRestored(restoredDomainObject);
				}
			}
		}
	}

	protected class StatusListener extends CompositeEditorModelAdapter {
		String status = null;
		boolean beep = false;

		protected void setStatus(String message, boolean beep) {
			this.status = message;
			this.beep = beep;
		}

		protected void clearStatus() {
			status = null;
			beep = false;
		}

		public String getStatus() {
			return status;
		}

		public boolean getBeep() {
			return beep;
		}
	}

	protected boolean isProviderShown(Window win, String editorName, String subtitle) {
		return isProviderShown(win, editorName + " - " + subtitle);
	}

	private boolean isProviderShown(Window win, String title) {
		if (isLabelInContainer(win, title)) {
			return true;
		}
		Window[] wins = win.getOwnedWindows();
		for (Window win2 : wins) {
			if (isProviderShown(win2, title)) {
				return true;
			}
		}
		return false;
	}

	private boolean isLabelInContainer(Container container, String title) {
		Component[] comps = container.getComponents();
		for (Component comp : comps) {
			if (comp instanceof JLabel) {
				JLabel label = (JLabel) comp;
				String text = runSwing(() -> label.getText());
				if (title.equals(text)) {
					return true;
				}
			}
			else if (comp instanceof Container) {
				if (isLabelInContainer((Container) comp, title)) {
					return true;
				}
			}
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	private void removeTableCellEditorsFocusLostListener() {

		// 
		// Note: black magic code to disable focusLost from cancelling the current editor session
		//

		JTable table = getTable();
		Map<Class<?>, ?> editors =
			(Map<Class<?>, ?>) getInstanceField("defaultEditorsByColumnClass", table);
		Collection<?> values = editors.values();
		for (Object editor : values) {
			removeFocusListener(editor);
		}

		TableColumnModel columnModel = table.getColumnModel();
		int n = columnModel.getColumnCount();
		for (int i = 0; i < n; i++) {
			TableColumn column = columnModel.getColumn(i);
			TableCellEditor cellEditor = column.getCellEditor();
			removeFocusListener(cellEditor);
		}
	}

	private void removeFocusListener(Object editor) {

		if (editor == null) {
			return;
		}

		Component c = null;
		if (editor instanceof Component) {
			c = (Component) editor;
		}

		if (editor instanceof DefaultCellEditor) {
			c = ((DefaultCellEditor) editor).getComponent();
		}

		if (c == null) {
			return;
		}

		FocusListener[] focusListeners = c.getFocusListeners();
		for (FocusListener focusListener : focusListeners) {
			Class<? extends FocusListener> clazz = focusListener.getClass();
			String name = clazz.getName();
			if (name.contains("ghidra")) {
				c.removeFocusListener(focusListener);
			}

		}
	}

	protected void selectAllInCellEditor() {
		runSwing(() -> ((JTextField) getTable().getEditorComponent()).selectAll());
	}

	protected void deleteAllInCellEditor() {
		runSwing(() -> {
			Object editorComponent = getTable().getEditorComponent();
			if (editorComponent instanceof JTextField) {
				((JTextField) editorComponent).setText("");
			}
			else if (editorComponent instanceof JPanel) {
				DataTypeSelectionEditor dataTypeSelectionEditor = getDataTypeSelectionEditor();
				assertNotNull("Could not find data type editor when attempting to edit a data type",
					dataTypeSelectionEditor);
				dataTypeSelectionEditor.setCellEditorValue(null);
			}
			else {
				Assert.fail("Unexpected cell editor");
			}
		});

		waitForSwing();
	}

	protected JTextField getCellEditorTextField() {
		Object editorComponent = getTable().getEditorComponent();
		if (editorComponent instanceof JTextField) {
			return (JTextField) editorComponent;
		}

		fail("Either not editing, or editing a field that is a custom editor (not a text field)");
		return null;
	}

	protected JTextField getDataTypeEditorTextField() {
		Object editorComponent = getTable().getEditorComponent();
		if (editorComponent instanceof JPanel) {
			DataTypeSelectionEditor dataTypeSelectionEditor = getDataTypeSelectionEditor();
			assertNotNull("Could not find data type editor when attempting to edit a data type",
				dataTypeSelectionEditor);
			return dataTypeSelectionEditor.getDropDownTextField();
		}

		fail("Either not editing, or editing the data type cell");
		return null;
	}

	protected JTextField checkForActiveEditorTextField() {
		Object editorComponent = getTable().getEditorComponent();
		if (editorComponent instanceof JTextField) {
			return (JTextField) editorComponent;
		}
		else if (editorComponent instanceof JPanel) {
			DataTypeSelectionEditor dataTypeSelectionEditor = getDataTypeSelectionEditor();
			assertNotNull("Could not find data type editor when attempting to edit a data type",
				dataTypeSelectionEditor);
			return dataTypeSelectionEditor.getDropDownTextField();
		}

		return null;
	}

	protected Component getKeyEventDestination() {

		JTextField textField = checkForActiveEditorTextField();
		if (textField != null) {
			return textField;
		}
		return getTable();
	}

	protected JTextField getActiveEditorTextField() {

		JTextField editorField = checkForActiveEditorTextField();
		assertNotNull("Not editing", editorField);
		return editorField;
	}

	protected void typeInCellEditor(String text) {
		triggerText(getActiveEditorTextField(), text);
	}

	protected void triggerActionInCellEditor(int keyCode) {
		triggerActionKey(getActiveEditorTextField(), 0, keyCode);
	}

	protected void triggerActionInCellEditor(int modifiers, int keyCode) {
		triggerActionKey(getActiveEditorTextField(), modifiers, keyCode);
	}

	private DataTypeSelectionEditor getDataTypeSelectionEditor() {
		Component editorComponent = getTable().getEditorComponent();
		if (editorComponent instanceof JPanel) {
			Object editor = getTable().getCellEditor();
			DataTypeSelectionEditor internalEditor =
				(DataTypeSelectionEditor) getInstanceField("editor", editor);
			return internalEditor;
		}

		return null;
	}

	protected void doubleClickTableCell(int row, int column) throws Exception {
		clickTableCell(getTable(), row, column, 2);
		// Double click a second time if not editing,
		// since editing sometimes gets canceled by a selection event in the TestEnv
		// if you have done a table.moveColumn().
		if (!model.isEditingField()) {
			clickTableCell(getTable(), row, column, 2);
		}
	}

	protected void assertIsEditingField(int row, int modelColumn) {
		String info = "Should be editing [row,modelColumn] of [" + row + "," + modelColumn + "] ";
		assertTrue(info + "but is not.", model.isEditingField());
		assertEquals(info + "but row is: " + model.getRow(), row, model.getRow());
		assertEquals(info + "but column is: " + model.getColumn(), modelColumn, model.getColumn());
	}

	protected void assertNotEditingField() {
		assertTrue("Editing cell when it should not be.", !model.isEditingField());
	}

	protected void assertStatus(String status) {
		assertEquals(status, model.getStatus());
	}

	/**
	 * @param string
	 * @param row
	 * @param modelColumn
	 */
	protected void assertCellString(String string, int row, int modelColumn) {
		Class<?> columnClass = model.getColumnClass(modelColumn);
		if (columnClass == DataTypeInstance.class) {
			DataTypeInstance dti = (DataTypeInstance) model.getValueAt(row, modelColumn);
			assertEquals(string, dti.getDataType().getDisplayName());
		}
		else {
			assertEquals(string, model.getValueAt(row, modelColumn));
		}
	}

	protected void checkEnablement(CompositeEditorAction action, boolean expectedEnablement) {
		AtomicBoolean result = new AtomicBoolean();
		runSwing(() -> result.set(action.isEnabledForContext(provider.getActionContext(null))));
		boolean actionEnablement = result.get();
		assertEquals(action.getName() + " is unexpectedly " +
			(actionEnablement ? "enabled" : "disabled") + ".", expectedEnablement,
			actionEnablement);
	}

	protected void assertIsInternallyAligned(boolean aligned) {
		assertEquals(aligned, ((CompEditorModel) model).isAligned());
	}

	protected void assertPackingValue(int value) {
		assertEquals(value, ((CompEditorModel) model).getPackingValue());
	}

	protected void assertMinimumAlignmentType(AlignmentType alignmentType) {
		assertEquals(alignmentType, ((CompEditorModel) model).getMinimumAlignmentType());
	}

	protected void assertMinimumAlignmentValue(int value) {
		assertEquals(value, ((CompEditorModel) model).getMinimumAlignment());
	}

	protected void assertActualAlignment(int value) {
		assertEquals(value, ((CompEditorModel) model).getActualAlignment());
	}

	protected void assertLength(int value) {
		assertEquals(value, ((CompEditorModel) model).getLength());
	}
}
