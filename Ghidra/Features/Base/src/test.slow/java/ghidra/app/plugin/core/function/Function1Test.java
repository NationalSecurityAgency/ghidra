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
package ghidra.app.plugin.core.function;

import static org.junit.Assert.*;

import java.awt.Component;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.cmd.function.*;
import ghidra.app.cmd.refs.AddStackRefCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.analysis.AutoAnalysisPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.data.DataPlugin;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.plugin.core.highlight.SetHighlightPlugin;
import ghidra.app.plugin.core.navigation.*;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.app.util.viewer.field.VariableNameFieldFactory;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;
import ghidra.util.task.TaskMonitorAdapter;

public class Function1Test extends AbstractGhidraHeadedIntegrationTest {

	private static final int DIALOG_WAIT_TIME = 3000;

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private FunctionPlugin fp;
	private DisassemblerPlugin dp;
	private DockingActionIf createFunction;
	private DockingActionIf createThunk;
	private DockingActionIf editThunk;
	private DockingActionIf revertThunk;
	private DockingActionIf deleteFunction;
	private DockingActionIf editComment;
	private DockingActionIf deleteComment;
	private DockingActionIf byteCycleAction;
	private DockingActionIf floatCycleAction;
	private DockingActionIf createArray;
	private DockingActionIf createPointer;
	private DockingActionIf clearFunctionReturnTypeAction;
	private DockingActionIf deleteFunctionVar;
	private DockingActionIf chooseDataType;

	public Function1Test() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testEnablement() throws Exception {
		ActionContext actionContext = cb.getProvider().getActionContext(null);
		assertNull(actionContext);
		actionContext = new ActionContext();
		assertTrue(!createFunction.isEnabledForContext(actionContext));
		assertTrue(!createThunk.isEnabledForContext(actionContext));
		assertTrue(!editThunk.isEnabledForContext(actionContext));
		assertTrue(!revertThunk.isEnabledForContext(actionContext));
		assertTrue(!deleteFunction.isEnabledForContext(actionContext));
		assertTrue(!editComment.isEnabledForContext(actionContext));
		assertTrue(!deleteComment.isEnabledForContext(actionContext));
		env.showTool();
		loadProgram("notepad");

		deleteExistingFunction(addr("0x1006420"));
		assertTrue(cb.goToField(addr("0x1006420"), "Address", 0, 0));
		actionContext = cb.getProvider().getActionContext(null);
		assertTrue(createFunction.isEnabledForContext(actionContext));
		assertTrue(createThunk.isEnabledForContext(actionContext));
		assertTrue(!editThunk.isEnabledForContext(actionContext));
		assertTrue(!revertThunk.isEnabledForContext(actionContext));
		assertTrue(!deleteFunction.isEnabledForContext(actionContext));
		assertTrue(!editComment.isEnabledForContext(actionContext));
		assertTrue(!deleteComment.isEnabledForContext(actionContext));

		assertTrue(cb.goToField(addr("0x1001000"), "Address", 0, 0));
		actionContext = cb.getProvider().getActionContext(null);
		assertTrue(!createFunction.isEnabledForContext(actionContext));
		assertTrue(!createThunk.isEnabledForContext(actionContext));
		assertTrue(!editThunk.isEnabledForContext(actionContext));
		assertTrue(!revertThunk.isEnabledForContext(actionContext));
		assertTrue(!deleteFunction.isEnabledForContext(actionContext));
		assertTrue(!editComment.isEnabledForContext(actionContext));
		assertTrue(!deleteComment.isEnabledForContext(actionContext));

		assertTrue(cb.goToField(addr("0x1006420"), "Address", 0, 0));
		actionContext = cb.getProvider().getActionContext(null);
		performAction(createFunction, cb.getProvider(), true);
		waitForBusyTool();

		assertTrue(cb.goToField(addr("0x1006420"), VariableNameFieldFactory.FIELD_NAME, 1, 1, 0));
		actionContext = cb.getProvider().getActionContext(null);
		assertTrue(editComment.isEnabledForContext(actionContext));

		assertTrue(cb.goToField(addr("0x1006420"), "Function Signature", 0, 0));
		actionContext = cb.getProvider().getActionContext(null);
		assertTrue(!createFunction.isEnabledForContext(actionContext));
		assertTrue(!createThunk.isEnabledForContext(actionContext));
		assertTrue(editThunk.isEnabledForContext(actionContext));
		assertTrue(!revertThunk.isEnabledForContext(actionContext));
		assertTrue(deleteFunction.isEnabledForContext(actionContext));
		assertTrue(!editComment.isEnabledForContext(actionContext));
		assertTrue(!deleteComment.isEnabledForContext(actionContext));

		assertTrue(cb.goToField(addr("0x1006420"), "Variable Name", 1, 0, 0));
		actionContext = cb.getProvider().getActionContext(null);
		assertTrue(!createFunction.isEnabledForContext(actionContext));
		assertTrue(!createThunk.isEnabledForContext(actionContext));
		assertTrue(editThunk.isEnabledForContext(actionContext));
		assertTrue(!revertThunk.isEnabledForContext(actionContext));
		assertTrue(!deleteFunction.isEnabledForContext(actionContext));
		assertTrue(editComment.isEnabledForContext(actionContext));
		assertTrue(!deleteComment.isEnabledForContext(actionContext));

		createThunk(addr("0x10030d2"), "comdlg32.dll::CommDlgExtendedError", true);

		assertTrue(cb.goToField(addr("0x10030d2"), "Function Signature", 0, 0));
		actionContext = cb.getProvider().getActionContext(null);
		assertTrue(!createFunction.isEnabledForContext(actionContext));
		assertTrue(!createThunk.isEnabledForContext(actionContext));
		assertTrue(editThunk.isEnabledForContext(actionContext));
		assertTrue(revertThunk.isEnabledForContext(actionContext));
		assertTrue(deleteFunction.isEnabledForContext(actionContext));
		assertTrue(!editComment.isEnabledForContext(actionContext));
		assertTrue(!deleteComment.isEnabledForContext(actionContext));

		closeProgram();
		actionContext = cb.getProvider().getActionContext(null);
		assertNull(actionContext);
		actionContext = new ActionContext();
		assertTrue(!createFunction.isEnabledForContext(actionContext));
		assertTrue(!deleteFunction.isEnabledForContext(actionContext));
		assertTrue(!editThunk.isEnabledForContext(actionContext));
		assertTrue(!revertThunk.isEnabledForContext(actionContext));
		assertTrue(!editComment.isEnabledForContext(actionContext));
		assertTrue(!deleteComment.isEnabledForContext(actionContext));

	}

	@Test
	public void testCreateThunkFunctionExternalDefault() throws Exception {
		env.showTool();
		loadProgram("notepad");

		deleteExistingFunction(addr("0x1006420"));

		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		ExternalReference extRef =
			(ExternalReference) refMgr.getPrimaryReferenceFrom(addr("0x10012f4"), 0);
		Address toAddress = extRef.getToAddress();
		Function function = listing.getFunctionAt(toAddress);
		if (function != null) {
			deleteExistingFunction(toAddress);
		}

		assertNull(program.getListing().getFunctionAt(addr("0x1006420")));

		Function thunk = createThunk(addr("0x10030d2"), "comdlg32.dll::CommDlgExtendedError", true);

		cb.goToField(addr("0x10030d2"), "Function Signature", 0, 0);
		assertEquals("thunk undefined CommDlgExtendedError()", cb.getCurrentFieldText());

		Function extFunc = listing.getFunctionAt(toAddress);
		assertNotNull(extFunc);

		assertTrue(thunk.getThunkedFunction(false) == extFunc);
		assertEquals("undefined CommDlgExtendedError()", extFunc.getPrototypeString(false, false));

		exerciseThunkPassThru(extFunc, thunk);

	}

	@Test
	public void testCreateThunkFunctionExternalNonDefault() throws Exception {
		env.showTool();
		loadProgram("notepad");

		deleteExistingFunction(addr("0x1006420"));

		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		ExternalReference extRef =
			(ExternalReference) refMgr.getPrimaryReferenceFrom(addr("0x10012f4"), 0);
		Address toAddress = extRef.getToAddress();
		Function function = listing.getFunctionAt(toAddress);
		if (function != null) {
			deleteExistingFunction(toAddress);
		}

		assertNull(program.getListing().getFunctionAt(addr("0x1006420")));

		createLabel(addr("0x10030d2"), "Foo");

		Function thunk = createThunk(addr("0x10030d2"), "comdlg32.dll::CommDlgExtendedError", true);

		cb.goToField(addr("0x10030d2"), "Function Signature", 0, 0);
		assertEquals("thunk undefined Foo()", cb.getCurrentFieldText());

		Function extFunc = listing.getFunctionAt(toAddress);
		assertNotNull(extFunc);

		assertTrue(thunk.getThunkedFunction(false) == extFunc);
		assertEquals("undefined CommDlgExtendedError()", extFunc.getPrototypeString(false, false));

		exerciseThunkPassThru(extFunc, thunk);

	}

	@Test
	public void testCreateThunkFunctionLocalDefault() throws Exception {
		env.showTool();
		loadProgram("notepad");

		Listing listing = program.getListing();

		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test",
			new ProgramSelection(addr("0x10030de"), addr("0x10030de")), program));
		waitForSwing();

		Function thunk = createThunk(addr("0x10030de"), "entry", false);

		cb.goToField(addr("0x10030de"), "Function Signature", 0, 0);
		assertEquals("thunk undefined entry()", cb.getCurrentFieldText());

		Function entryFunc = listing.getFunctionAt(addr("0x1006420"));
		assertNotNull(entryFunc);
		assertEquals("undefined entry()", entryFunc.getPrototypeString(false, false));

		assertTrue(thunk.getThunkedFunction(false) == entryFunc);

		exerciseThunkPassThru(entryFunc, thunk);
	}

	@Test
	public void testCreateThunkFunctionLocalNonDefault() throws Exception {
		env.showTool();
		loadProgram("notepad");

		Listing listing = program.getListing();

		createLabel(addr("0x10030de"), "Foo");

		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test",
			new ProgramSelection(addr("0x10030de"), addr("0x10030de")), program));
		waitForSwing();

		Function thunk = createThunk(addr("0x10030de"), "entry", false);

		cb.goToField(addr("0x10030de"), "Function Signature", 0, 0);
		assertEquals("thunk undefined Foo()", cb.getCurrentFieldText());

		Function entryFunc = listing.getFunctionAt(addr("0x1006420"));
		assertNotNull(entryFunc);
		assertEquals("undefined entry()", entryFunc.getPrototypeString(false, false));

		assertTrue(thunk.getThunkedFunction(false) == entryFunc);

		exerciseThunkPassThru(entryFunc, thunk);
	}

	@Test
	public void testEditThunkFunction() throws Exception {
		env.showTool();
		loadProgram("notepad");

		createThunk(addr("0x10030d2"), "comdlg32.dll::CommDlgExtendedError", true);

		assertTrue(cb.goToField(addr("0x10030d2"), "Function Signature", 0, 0));

		performAction(editThunk, cb.getProvider(), false);

		ThunkReferenceAddressDialog thunkDlg =
			waitForDialogComponent(null, ThunkReferenceAddressDialog.class, 100);
		assertNotNull(thunkDlg);
		JTextField thunkedEntryField = findComponent(thunkDlg, JTextField.class);
		assertEquals("comdlg32.dll::CommDlgExtendedError", thunkedEntryField.getText());
		setText(thunkedEntryField, "ADVAPI32.dll::RegQueryValueExW");
		pressButtonByText(thunkDlg, "OK");
		waitForSwing();
		waitForBusyTool();

		Function func = program.getListing().getFunctionAt(addr("0x10030d2"));
		assertNotNull(func);
		assertTrue(func.isThunk());
		assertEquals("RegQueryValueExW", func.getName());

		undo(program);// undo changed function

		assertTrue(func.isThunk());
		assertEquals("CommDlgExtendedError", func.getName());

		redo(program);// redo changed function

		assertTrue(func.isThunk());
		assertEquals("RegQueryValueExW", func.getName());
	}

	@Test
	public void testRevertThunkFunction() throws Exception {
		env.showTool();
		loadProgram("notepad");

		Function func = createThunk(addr("0x10030d2"), "comdlg32.dll::CommDlgExtendedError", true);

		assertTrue(cb.goToField(addr("0x10030d2"), "Function Signature", 0, 0));

		performAction(revertThunk, cb.getProvider(), false);

		OptionDialog optDlg = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optDlg);
		assertEquals("Revert Thunk Confirmation", optDlg.getTitle());
		pressButton(findButtonByText(optDlg, "Yes"));

		waitForBusyTool();

		assertFalse(func.isThunk());
		assertEquals("FUN_010030d2", func.getName());

		undo(program);// undo changed function

		assertTrue(func.isThunk());
		assertEquals("CommDlgExtendedError", func.getName());

		int txId = program.startTransaction("Set Name");
		try {
			func.setName("foo", SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(txId, true);
		}

		performAction(revertThunk, cb.getProvider(), false);
		waitForBusyTool();

		optDlg = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optDlg);
		assertEquals("Revert Thunk Confirmation", optDlg.getTitle());
		pressButton(findButtonByText(optDlg, "Yes"));

		waitForBusyTool();

		assertFalse(func.isThunk());
		assertEquals("foo", func.getName());

	}

	@Test
	public void testSetThunkedFunction() throws Exception {
		env.showTool();
		loadProgram("notepad");

		createFunctionAt("0x1006420");
		Function func = program.getListing().getFunctionAt(addr("0x1006420"));
		assertNotNull(func);

		assertTrue(!func.isThunk());
		assertEquals("entry", func.getName());
		assertTrue(func.getLocalVariables().length != 0);

		assertTrue(cb.goToField(addr("0x1006420"), "Function Signature", 0, 0));

		performAction(editThunk, cb.getProvider(), false);

		waitForSwing();

		ThunkReferenceAddressDialog thunkDlg =
			waitForDialogComponent(null, ThunkReferenceAddressDialog.class, 100);
		assertNotNull(thunkDlg);
		JTextField thunkedEntryField = findComponent(thunkDlg, JTextField.class);
		assertEquals("", thunkedEntryField.getText());
		setText(thunkedEntryField, "ADVAPI32.dll::RegQueryValueExW");
		pressButtonByText(thunkDlg, "OK");
		waitForSwing();
		waitForBusyTool();

		assertTrue(func.isThunk());
		assertEquals("entry", func.getName());
		assertTrue(func.getLocalVariables().length == 0);
		assertEquals("RegQueryValueExW", func.getThunkedFunction(true).getName());

		undo(program);// undo changed function

		assertTrue(!func.isThunk());
		assertEquals("entry", func.getName());
		assertTrue(func.getLocalVariables().length != 0);

		redo(program);// redo changed function

		assertTrue(func.isThunk());
		assertEquals("entry", func.getName());
		assertTrue(func.getLocalVariables().length == 0);
		assertEquals("RegQueryValueExW", func.getThunkedFunction(true).getName());
	}

	@Test
	public void testDeleteThunkFunction() throws Exception {
		env.showTool();
		loadProgram("notepad");

		createThunk(addr("0x10030d2"), "comdlg32.dll::CommDlgExtendedError", true);

		assertTrue(cb.goToField(addr("0x10030d2"), "Address", 0, 0));

		performAction(deleteFunction, cb.getProvider(), true);
		waitForBusyTool();

		assertNull(program.getListing().getFunctionAt(addr("0x10030d2")));
		undo(program);// undo delete function
		assertNotNull(program.getListing().getFunctionAt(addr("0x10030d2")));
		redo(program);// redo delete function
		assertNull(program.getListing().getFunctionAt(addr("0x10030d2")));
	}

	@Test
	public void testCreateFunction() throws Exception {
		env.showTool();
		loadProgram("notepad");
		cb.goToField(addr("0x1006420"), "Address", 0, 0);

		createFunctionAtEntry();
		waitForBusyTool();

		assertNotNull(program.getListing().getFunctionAt(addr("0x1006420")));

		cb.goToField(addr("0x1006420"), "Function Signature", 0, 0);
		assertEquals("undefined entry()", cb.getCurrentFieldText());

		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 0, 0, 0));
		assertEquals("undefined", cb.getCurrentFieldText());
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 1, 0, 0));
		assertEquals("undefined4", cb.getCurrentFieldText());
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 2, 0, 0));
		assertEquals("undefined4", cb.getCurrentFieldText());
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 3, 0, 0));
		assertEquals("undefined4", cb.getCurrentFieldText());
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 4, 0, 0));
		assertEquals("undefined4", cb.getCurrentFieldText());

		cb.goToField(addr("0x1006443"), "Operands", 0, 0);
		assertEquals("dword ptr [EBP + local_1c],ESP", cb.getCurrentFieldText());

		undo(program);
		assertNull(program.getListing().getFunctionAt(addr("0x1006420")));

		cb.goToField(addr("0x1006443"), "Operands", 0, 0);
		assertEquals("dword ptr [EBP + -0x18],ESP", cb.getCurrentFieldText());

		redo(program);
		assertNotNull(program.getListing().getFunctionAt(addr("0x1006420")));

		cb.goToField(addr("0x1006443"), "Operands", 0, 0);
		assertEquals("dword ptr [EBP + local_1c],ESP", cb.getCurrentFieldText());

	}

	@Test
	public void testDeleteFunction() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();

		cb.goToField(addr("0x1006420"), "Function Signature", 0, 0);
		assertEquals("undefined entry()", cb.getCurrentFieldText());

		performAction(deleteFunction, cb.getProvider(), true);
		waitForBusyTool();
		assertNull(program.getListing().getFunctionAt(addr("0x1006420")));
		undo(program);// undo delete function
		assertNotNull(program.getListing().getFunctionAt(addr("0x1006420")));
		redo(program);// redo delete function
		assertNull(program.getListing().getFunctionAt(addr("0x1006420")));
	}

	@Test
	public void testStackVariableComment() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Name", 1, 0, 0));
		assertTrue(!deleteComment.isEnabledForContext(cb.getProvider().getActionContext(null)));
		performAction(editComment, cb.getProvider(), false);
		waitForBusyTool();
		VariableCommentDialog vcd = waitForDialogComponent(tool.getToolFrame(),
			VariableCommentDialog.class, DIALOG_WAIT_TIME);
		assertNotNull(vcd);
		JTextArea textArea = findComponent(vcd, JTextArea.class);
		triggerText(textArea, "My New Comment");
		pressButtonByText(vcd.getComponent(), "OK");
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Comment", 0, 0, 0));
		assertEquals("My New Comment", cb.getCurrentFieldText());
		assertTrue(deleteComment.isEnabledForContext(cb.getProvider().getActionContext(null)));

		performAction(editComment, cb.getProvider(), false);
		vcd = waitForDialogComponent(tool.getToolFrame(), VariableCommentDialog.class,
			DIALOG_WAIT_TIME);
		textArea = findComponent(vcd, JTextArea.class);
		triggerText(textArea, "more stuff");
		pressButtonByText(vcd.getComponent(), "OK");
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Comment", 0, 0, 0));
		assertEquals("more stuff", cb.getCurrentFieldText());
		undo(program);
		assertEquals("My New Comment", cb.getCurrentFieldText());
		assertTrue(deleteComment.isEnabledForContext(cb.getProvider().getActionContext(null)));

		redo(program);
		assertEquals("more stuff", cb.getCurrentFieldText());
		assertTrue(deleteComment.isEnabledForContext(cb.getProvider().getActionContext(null)));

		performAction(deleteComment, cb.getProvider(), true);
		assertFalse(cb.goToField(addr("0x1006420"), "Variable Comment", 0, 0, 0));

		undo(program);
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Comment", 0, 0, 0));
		assertEquals("more stuff", cb.getCurrentFieldText());
	}

	@Test
	public void testReturnTypeCycleActions() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 0, 0));

		Function function = program.getFunctionManager().getFunctionAt(addr("0x1006420"));
		assertEquals("undefined entry()", function.getPrototypeString(false, false));
		doCycleAction(byteCycleAction);

		assertEquals("byte entry(void)", function.getPrototypeString(false, false));

		doCycleAction(byteCycleAction);
		assertEquals("word entry(void)", function.getPrototypeString(false, false));

		doCycleAction(byteCycleAction);
		assertEquals("dword entry(void)", function.getPrototypeString(false, false));

		doCycleAction(byteCycleAction);
		assertEquals("qword entry(void)", function.getPrototypeString(false, false));

		doCycleAction(byteCycleAction);
		assertEquals("byte entry(void)", function.getPrototypeString(false, false));

		doCycleAction(floatCycleAction);
		assertEquals("float entry(void)", function.getPrototypeString(false, false));

		doCycleAction(floatCycleAction);
		assertEquals("double entry(void)", function.getPrototypeString(false, false));

		doCycleAction(floatCycleAction);
		assertEquals("float entry(void)", function.getPrototypeString(false, false));
	}

	@Test
	public void testStackVarTypeCycleActions() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 2, 0, 0));
		DockingActionIf clearDataType = getAction(fp, "Define undefined");
		performAction(clearDataType, cb.getProvider(), true);
		program.flushEvents();
		waitForSwing();
		cb.updateNow();
		assertEquals("undefined", cb.getCurrentFieldText());

		doCycleAction(byteCycleAction);
		assertEquals("byte", cb.getCurrentFieldText());

		doCycleAction(byteCycleAction);
		assertEquals("word", cb.getCurrentFieldText());

		doCycleAction(byteCycleAction);
		assertEquals("dword", cb.getCurrentFieldText());

		doCycleAction(byteCycleAction);
		assertEquals("qword", cb.getCurrentFieldText());

		doCycleAction(byteCycleAction);
		assertEquals("byte", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("float", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("double", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("float", cb.getCurrentFieldText());

	}

	@Test
	public void testParamCycleCustomStorageActions() throws Exception {
		env.showTool();
		loadProgram("notepad");
		Address a = addr("0x10059a3");
		assertTrue(cb.goToField(a, "Address", 0, 0));

		Function function = createAFunction();
		setCustomParameterStorage(function, true);

		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));
		DockingActionIf clearDataType = getAction(fp, "Define undefined");
		performAction(clearDataType, cb.getProvider(), true);
		waitForBusyTool();

		assertEquals("undefined", cb.getCurrentFieldText());

		doCycleAction(byteCycleAction);
		assertEquals("byte", cb.getCurrentFieldText());

		assertTrue(cb.goToField(a, "Function Signature", 0, 0));
		assertEquals("undefined FUN_010059a3(undefined4 param_1, byte param_2, undefined4 param_3)",
			cb.getCurrentFieldText());

		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));

		doCycleAction(byteCycleAction);
		assertEquals("word", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);
		assertEquals("undefined FUN_010059a3(undefined4 param_1, word param_2, undefined4 param_3)",
			cb.getCurrentFieldText());
		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));

		doCycleAction(byteCycleAction);
		assertEquals("dword", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);
		assertEquals(
			"undefined FUN_010059a3(undefined4 param_1, dword param_2, undefined4 param_3)",
			cb.getCurrentFieldText());
		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));

		// check that you cycle past qword because there is not room on the stack
		doCycleAction(byteCycleAction);
		assertEquals("undefined", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);

		assertEquals(
			"undefined FUN_010059a3(undefined4 param_1, undefined param_2, undefined4 param_3)",
			cb.getCurrentFieldText());

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));
		clearDataType = getAction(fp, "Define undefined");
		performAction(clearDataType, cb.getProvider(), true);
		waitForBusyTool();

		assertEquals("undefined", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("float", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("double", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("float", cb.getCurrentFieldText());

	}

	@Test
	public void testParamCycleDynamicStorageActions() throws Exception {
		env.showTool();
		loadProgram("notepad");
		Address a = addr("0x10059a3");
		assertTrue(cb.goToField(a, "Address", 0, 0));

		Function function = createAFunction();
		setCustomParameterStorage(function, false);

		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));
		DockingActionIf clearDataType = getAction(fp, "Define undefined");
		performAction(clearDataType, cb.getProvider(), true);
		waitForBusyTool();

		assertEquals("undefined", cb.getCurrentFieldText());

		doCycleAction(byteCycleAction);
		assertEquals("byte", cb.getCurrentFieldText());
		waitForBusyTool();

		assertTrue(cb.goToField(a, "Function Signature", 0, 0));

		String text = cb.getCurrentFieldText();
		assertTrue(
			text.contains("FUN_010059a3(undefined4 param_1, byte param_2, undefined4 param_3)"));

		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));

		doCycleAction(byteCycleAction);
		assertEquals("word", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);
		text = cb.getCurrentFieldText();
		assertTrue(
			text.contains("FUN_010059a3(undefined4 param_1, word param_2, undefined4 param_3)"));

		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));

		doCycleAction(byteCycleAction);
		assertEquals("dword", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);

		text = cb.getCurrentFieldText();
		assertTrue(
			text.contains("FUN_010059a3(undefined4 param_1, dword param_2, undefined4 param_3)"));

		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));

		// check that you cycle to qword because storage is dynamic
		doCycleAction(byteCycleAction);
		assertEquals("qword", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);

		text = cb.getCurrentFieldText();
		assertTrue(
			text.contains("FUN_010059a3(undefined4 param_1, qword param_2, undefined4 param_3)"));

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));
		clearDataType = getAction(fp, "Define undefined");
		performAction(clearDataType, cb.getProvider(), true);
		waitForBusyTool();

		assertEquals("undefined", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("float", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("double", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("float", cb.getCurrentFieldText());

	}

	@Test
	public void testParamCycleActions2() throws Exception {
		env.showTool();
		loadProgram("notepad");
		Address a = addr("0x100248f");
		cb.goToField(a, "Address", 0, 0);

		DockingActionIf action = getAction(dp, "Disassemble");
		assertNotNull(action);
		performAction(action, cb.getProvider(), true);
		waitForBusyTool();

		Function function = program.getListing().getFunctionAt(addr("0x100248f"));
		assertNotNull(function);// function created by FunctionStartAnalyzer

		CompoundCmd cmd = new CompoundCmd("test");
		for (Parameter parm : function.getParameters()) {
			cmd.add(new DeleteVariableCmd(parm));
		}
		cmd.add(new AddStackParameterCommand(function, 0x4, "param_1", Undefined4DataType.dataType,
			0, SourceType.USER_DEFINED));
		cmd.add(new AddStackParameterCommand(function, 0xc, "param_2", Undefined4DataType.dataType,
			1, SourceType.USER_DEFINED));
		cmd.add(new AddStackParameterCommand(function, 0x10, "param_3", Undefined4DataType.dataType,
			2, SourceType.USER_DEFINED));
		cmd.add(new AddStackParameterCommand(function, 0x18, "param_4", Undefined4DataType.dataType,
			3, SourceType.USER_DEFINED));
		tool.execute(cmd, program);
		waitForBusyTool();

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));
		DockingActionIf clearDataType = getAction(fp, "Define undefined");
		performAction(clearDataType, cb.getProvider(), true);
		waitForBusyTool();

		assertEquals("undefined", cb.getCurrentFieldText());

		doCycleAction(byteCycleAction);
		assertEquals("byte", cb.getCurrentFieldText());
		waitForBusyTool();
		cb.goToField(a, "Function Signature", 0, 0);

		String text = cb.getCurrentFieldText();
		assertTrue(text.contains(
			"FUN_0100248f(undefined4 param_1, undefined4 param_2, byte param_3, undefined4 param_4)"));

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));

		doCycleAction(byteCycleAction);
		assertEquals("word", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);

		text = cb.getCurrentFieldText();
		assertTrue(text.contains(
			"FUN_0100248f(undefined4 param_1, undefined4 param_2, word param_3, undefined4 param_4)"));

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));

		doCycleAction(byteCycleAction);
		assertEquals("dword", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);

		text = cb.getCurrentFieldText();
		assertTrue(text.contains(
			"FUN_0100248f(undefined4 param_1, undefined4 param_2, dword param_3, undefined4 param_4)"));

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));

		doCycleAction(byteCycleAction);
		assertEquals("qword", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);

		text = cb.getCurrentFieldText();
		assertTrue(text.contains(
			"FUN_0100248f(undefined4 param_1, undefined4 param_2, qword param_3, undefined4 param_4)"));

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));

		doCycleAction(byteCycleAction);
		assertEquals("byte", cb.getCurrentFieldText());
		cb.goToField(a, "Function Signature", 0, 0);

		text = cb.getCurrentFieldText();
		assertTrue(text.contains(
			"FUN_0100248f(undefined4 param_1, undefined4 param_2, byte param_3, undefined4 param_4)"));

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));

		doCycleAction(floatCycleAction);
		assertEquals("float", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("double", cb.getCurrentFieldText());

		doCycleAction(floatCycleAction);
		assertEquals("float", cb.getCurrentFieldText());

	}

	@Test
	public void testArray() throws Exception {
		env.showTool();
		loadProgram("notepad");
		Address a = addr("0x10059a3");
		cb.goToField(a, "Address", 0, 0);

		createAFunction();
		// put a byte at local_8
		Function function = program.getListing().getFunctionAt(a);
		Variable[] vars = function.getLocalVariables(VariableFilter.STACK_VARIABLE_FILTER);
		int transactionID = program.startTransaction("test");
		try {
			DataType byteDT = program.getDataTypeManager().addDataType(new ByteDataType(),
				DataTypeConflictHandler.DEFAULT_HANDLER);
			vars[1].setDataType(byteDT, SourceType.ANALYSIS);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForSwing();
		cb.updateNow();

		assertTrue(cb.goToField(a, "Variable Type", 5, 0, 0));
		// go to local_c-- should be undefined4

		performAction(createArray, cb.getProvider(), false);
		waitForSwing();
		final NumberInputDialog d =
			env.waitForDialogComponent(NumberInputDialog.class, DIALOG_WAIT_TIME);

		assertNotNull(d);
		vars = function.getLocalVariables(VariableFilter.STACK_VARIABLE_FILTER);

		assertEquals(1, d.getMin());
		assertEquals(Integer.MAX_VALUE, d.getMax());

		final AtomicInteger result = new AtomicInteger(0);
		runSwing(() -> result.set(d.getValue()));
		assertEquals(12, result.get());

		runSwing(() -> d.setInput(4));

		pressButtonByText(d, "OK");
		program.flushEvents();
		waitForSwing();
		cb.updateNow();

		assertTrue(cb.goToField(a, "Variable Type", 5, 0, 0));
		// only array size of 1 should fit because of the byte created
		assertEquals("byte[4]", cb.getCurrentFieldText());
	}

	@Test
	public void testPointers() throws Exception {
		env.showTool();
		loadProgram("notepad");
		Address a = addr("0x10059a3");
		assertTrue(cb.goToField(a, "Address", 0, 0));

		createAFunction();

		assertTrue(cb.goToField(a, "Variable Type", 3, 0, 0));
		DockingActionIf clearDataType = getAction(fp, "Define undefined");
		performAction(clearDataType, cb.getProvider(), true);
		waitForBusyTool();

		DockingActionIf createByte = getAction(fp, "Define byte");

		performAction(createByte, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("byte", cb.getCurrentFieldText());

		performAction(createPointer, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("pointer", cb.getCurrentFieldText());

		performAction(createByte, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("byte *", cb.getCurrentFieldText());

		performAction(createPointer, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("byte * *", cb.getCurrentFieldText());

		clearDataType = getAction(fp, "Define undefined");
		performAction(clearDataType, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("undefined", cb.getCurrentFieldText());

	}

	@Test
	public void testRecentlyUsed() throws Exception {
		env.showTool();
		loadProgram("notepad");
		Address a = addr("0x10059a3");
		assertTrue(cb.goToField(a, "Address", 0, 0));

		createAFunction();

		assertTrue(cb.goToField(addr("0x1008393"), "Address", 0, 0));
		tool.addPlugin(DataPlugin.class.getName());
		DataPlugin dataPlugin = getPlugin(tool, DataPlugin.class);
		DockingActionIf createWord = getAction(dataPlugin, "Define word");
		performAction(createWord, cb.getProvider(), true);
		waitForBusyTool();

		assertTrue(cb.goToField(a, "Variable Type", 2, 0, 0));
		DockingActionIf recentlyUsed = getAction(fp, "Recently Used");
		assertTrue(recentlyUsed.isEnabledForContext(cb.getProvider().getActionContext(null)));
		performAction(recentlyUsed, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("word", cb.getCurrentFieldText());

		assertTrue(cb.goToField(a, "Function Signature", 0, 0));
		performAction(recentlyUsed, cb.getProvider(), true);
		waitForBusyTool();

		assertTrue(cb.getCurrentFieldText().startsWith("word"));
	}

	@Test
	public void testSetReturnTypeToVoid() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();
		assertTrue(cb.goToField(addr("0x1006420"), "Function Signature", 0, 0));
		assertEquals("undefined entry()", cb.getCurrentFieldText());
		DockingActionIf setVoid = getAction(fp, "Define void");
		performAction(setVoid, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("void entry(void)", cb.getCurrentFieldText());
	}

	@Test
	public void testRename() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();
		assertTrue(cb.goToField(addr("0x1006420"), "Function Signature", 0, 0));
		assertEquals("undefined entry()", cb.getCurrentFieldText());

		DockingActionIf rename = getAction(fp, "Rename Function");
		assertEquals("Rename Function...", rename.getPopupMenuData().getMenuPath()[1]);
		performAction(rename, cb.getProvider(), false);
		waitForBusyTool();

		AddEditDialog dialog = env.waitForDialogComponent(AddEditDialog.class, DIALOG_WAIT_TIME);
		assertNotNull(dialog);

		GhidraComboBox<?> combo = findComponent(dialog, GhidraComboBox.class);
		ComboBoxEditor editor = combo.getEditor();
		Component c = editor.getEditorComponent();
		triggerText(c, "hello");
		pressButtonByText(dialog, "OK");
		waitForBusyTool();

		assertEquals("undefined hello()", cb.getCurrentFieldText());
		undo(program);
		cb.updateNow();
		assertEquals("undefined entry()", cb.getCurrentFieldText());
		redo(program);
		cb.updateNow();
		assertEquals("undefined hello()", cb.getCurrentFieldText());
		rename = getAction(fp, "Rename Variable");
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Name", 1, 0, 0));
		assertEquals("Rename Variable...", rename.getPopupMenuData().getMenuPath()[1]);
		Function function = getFunction("hello");
		Variable[] vars = function.getLocalVariables();
		assertEquals(vars[0].getName(), cb.getCurrentFieldText());

		performAction(rename, cb.getProvider(), false);

		dialog = env.waitForDialogComponent(AddEditDialog.class, DIALOG_WAIT_TIME);
		assertNotNull(dialog);

		JComboBox<?> nameBox = (JComboBox<?>) getInstanceField("labelNameChoices", dialog);
		final JTextField editorField = (JTextField) nameBox.getEditor().getEditorComponent();
		assertNotNull(editorField);
		SwingUtilities.invokeAndWait(() -> editorField.setText("fred"));
		//typeText("fred");
		pressButtonByText(dialog, "OK");

		assertEquals("fred", cb.getCurrentFieldText());
		undo(program);
		vars = function.getLocalVariables();
		assertEquals(vars[0].getName(), cb.getCurrentFieldText());
		redo(program);

		// Need to jump back to the variable section, as the 'redo' function moves us to the
		// start of the instruction block.
		cb.goToField(addr("0x1006420"), "Variable Name", 1, 0, 0);
		assertEquals("fred", cb.getCurrentFieldText());

		DockingActionIf renameFunctionVar = getAction(fp, "Rename Function Variable");
		assertTrue(cb.goToField(addr("0x1006446"), "Operands", 0, 18));
		assertEquals("dword ptr [EBP + fred],0x0", cb.getCurrentFieldText());
		performAction(renameFunctionVar, cb.getProvider(), false);

		dialog = env.waitForDialogComponent(AddEditDialog.class, DIALOG_WAIT_TIME);
		assertNotNull(dialog);

		nameBox = (JComboBox<?>) getInstanceField("labelNameChoices", dialog);
		final JTextField editorField2 = (JTextField) nameBox.getEditor().getEditorComponent();
		assertNotNull(editorField);
		SwingUtilities.invokeAndWait(() -> editorField2.setText("bob"));

//
//		typeText("bob");
//		waitForSwing();
		pressButtonByText(dialog, "OK");
		waitForBusyTool();
		assertEquals("dword ptr [EBP + bob],0x0", cb.getCurrentFieldText());
		undo(program);
		cb.updateNow();
		assertEquals("dword ptr [EBP + fred],0x0", cb.getCurrentFieldText());
		redo(program);
		cb.updateNow();
		assertEquals("dword ptr [EBP + bob],0x0", cb.getCurrentFieldText());

	}

	@Test
	public void testClearReturnDataType() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 0, 0));
		doCycleAction(byteCycleAction);
		assertTrue(cb.goToField(addr("0x1006420"), "Function Signature", 0, 0));
		assertEquals("byte entry(void)", cb.getCurrentFieldText());

		assertTrue(cb.goToField(addr("0x1006420"), "Function Signature", 0, 0));
		performAction(clearFunctionReturnTypeAction, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("undefined entry()", cb.getCurrentFieldText());

		undo(program);
		cb.updateNow();
		assertEquals("byte entry(void)", cb.getCurrentFieldText());
		redo(program);
		cb.updateNow();
		assertEquals("undefined entry()", cb.getCurrentFieldText());

		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 1, 0, 0));
		assertTrue(cb.getCurrentFieldText().equals("undefined4"));
		performAction(clearFunctionReturnTypeAction, cb.getProvider(), true);
		waitForBusyTool();
		assertEquals("undefined", cb.getCurrentFieldText());

		undo(program);
		cb.updateNow();
		assertTrue(!cb.getCurrentFieldText().equals("undefined"));
		redo(program);
		cb.updateNow();
		assertEquals("undefined", cb.getCurrentFieldText());
	}

	@Test
	public void testDeleteStackVar() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Name", 3, 0, 0));
		Function function = getFunction("entry");
		Variable[] vars = function.getLocalVariables();
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] vrefs = refMgr.getReferencesTo(vars[2]);
		assertEquals(1, vrefs.length);
		Address refAddr = vrefs[0].getFromAddress();
		String varName = vars[2].getName();
		assertEquals(varName, cb.getCurrentFieldText());

		performAction(deleteFunctionVar, cb.getProvider(), true);
		waitForBusyTool();

		assertTrue(cb.goToField(addr("0x1006420"), "Variable Name", 3, 0, 0));
		vars = function.getLocalVariables();
		String varName2 = vars[1].getName();
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Name", 2, 0, 0));
		assertEquals(varName2, cb.getCurrentFieldText());

		assertTrue(cb.goToField(refAddr, OperandFieldFactory.FIELD_NAME, 0, 0));
		cb.updateNow();

		String fieldText = cb.getCurrentFieldText();
		assertTrue("Unexpected operand text: " + fieldText, fieldText.contains("[EBP + Stack["));

		undo(program);
		cb.updateNow();

		assertEquals(varName, cb.getCurrentFieldText());
		redo(program);
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x1006420"), "Variable Name", 2, 0, 0));
		assertEquals(varName2, cb.getCurrentFieldText());
	}

	@Test
	public void testStackXrefs() throws Exception {
		env.showTool();
		loadProgram("notepad");
		createFunctionAtEntry();
		// create a stack reference at 1006446 on operand 1.
		AddStackRefCmd cmd =
			new AddStackRefCmd(addr("0x1006446"), 1, -0x1c, SourceType.USER_DEFINED);
		tool.execute(cmd, program);
		waitForBusyTool();

		assertTrue(cb.goToField(addr("0x1006420"), "Variable XRef", 1, 0, 0));
		assertEquals("01006443(W), 01006446(*)  ", cb.getCurrentFieldText());
		click(cb, 2);

		Function function = getFunction("entry");
		Variable[] vars = function.getLocalVariables();

		assertEquals(addr("0x1006443"), cb.getCurrentAddress());
		assertTrue(cb.goToField(cb.getCurrentAddress(), OperandFieldFactory.FIELD_NAME, 0, 0));
		assertEquals("dword ptr [EBP + " + vars[1].getName() + "],ESP", cb.getCurrentFieldText());
		click(cb, 2);
		assertEquals(addr("0x1006420"), cb.getCurrentAddress());
		assertEquals(vars[1].getName(), cb.getCurrentFieldText());

		performAction(deleteFunctionVar, cb.getProvider(), true);
		waitForBusyTool();
		cb.goToField(addr("0x01006443"), "Operands", 0, 0);
		assertTrue(cb.getCurrentFieldText().indexOf("local") < 0);
		click(cb, 2);
		assertEquals("undefined entry()", cb.getCurrentFieldText());
	}

	@Test
	public void testRenameFunctionInOperand() throws Exception {
		env.showTool();
		loadProgram("notepad");
		Address a = addr("0x10059a3");
		assertTrue(cb.goToField(a, "Address", 0, 0));
		createAFunction();

		Function function = getFunction("FUN_010059a3");
		assertNotNull(function);

		assertTrue(cb.goToField(addr("0x1002318"), OperandFieldFactory.FIELD_NAME, 0, 10));
		assertEquals("FUN_010059a3", cb.getCurrentFieldText());
		DockingActionIf rename = getAction(fp, "Rename Function");
		assertTrue(rename.isEnabledForContext(cb.getProvider().getActionContext(null)));

		performAction(rename, cb.getProvider(), false);
		waitForBusyTool();

		AddEditDialog dialog = env.waitForDialogComponent(AddEditDialog.class, DIALOG_WAIT_TIME);
		assertNotNull(dialog);

		GhidraComboBox<?> combo = findComponent(dialog, GhidraComboBox.class);
		ComboBoxEditor editor = combo.getEditor();
		Component c = editor.getEditorComponent();
		triggerText(c, "hello");
		pressButtonByText(dialog.getComponent(), "OK");
		waitForBusyTool();

		assertEquals("hello", cb.getCurrentFieldText());

		assertEquals("hello", function.getName());
	}

	@Test
	public void testGetCalledAndGetCallingFunctions() throws Exception {
		env.showTool();

		loadProgram("notepad");

		createFunctionAtEntry();
		waitForBusyTool();

		Function entry = getFunction("entry");
		assertNotNull(entry);

		Set<Function> called = entry.getCalledFunctions(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(4, called.size());
		Set<Function> calling = entry.getCallingFunctions(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(0, calling.size());// nobody calls entry

		for (Function f : called) {
			Set<Function> calling_f = f.getCallingFunctions(TaskMonitorAdapter.DUMMY_MONITOR);
			assertTrue(calling_f.contains(entry));
		}
	}

	/**
	 * Tests that setting a function register param to have a data type larger than
	 * its storage allows will produce an error message in the status box, and not simply fail
	 * silently.
	 *
	 * Note: This is only to test changing the data type using the Choose Data Type
	 * action, NOT using the Edit Function window.
	 */
	@Test
	public void testInvalidDataTypeSize() throws Exception {

		env.showTool();
		loadProgram("notepad");
		Function f = createFunctionAtEntry();
		setCustomParameterStorage(f, true);

		assertTrue(cb.goToField(addr("0x1006420"), "Variable Type", 0, 0));

		performAction(chooseDataType, cb.getProvider(), false);
		DataTypeSelectionDialog dialog =
			waitForDialogComponent(null, DataTypeSelectionDialog.class, DIALOG_WAIT_TIME);

		setEditorText(dialog, "int[0x8888888]");

		// For the test to pass, the status field should show an error message containing
		// the following text (this is only a part of the status message, but is enough
		// to verify the test):
		assertTrue(dialog.getStatusText().contains("doesn't fit within"));
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void setEditorText(final DataTypeSelectionDialog dialog, final String text) {
		runSwing(() -> {
			DataTypeSelectionEditor editor = dialog.getEditor();
			editor.setCellEditorValueAsText(text);
			editor.stopCellEditing();
		});
		waitForSwing();
	}

	private void createLabel(Address addr, String name) throws Exception {
		int txId = program.startTransaction("Add label");
		try {
			program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(txId, true);
		}
		waitForSwing();
	}

	@SuppressWarnings("deprecation")
	private void exerciseThunkPassThru(Function thunkedFunc, Function thunk) throws Exception {
		String origThunkedName = thunkedFunc.getName();
		String origThunkName = thunk.getName();
		String finalName = null;
		int txId = program.startTransaction("Add params");
		try {

			boolean isDefault = thunk.getSymbol().getSource() == SourceType.DEFAULT;

			thunkedFunc.setName("Name1", SourceType.USER_DEFINED);
			assertEquals("Name1", thunkedFunc.getName());

			if (!isDefault) {
				assertEquals(origThunkName, thunk.getName());
				program.getSymbolTable().removeSymbolSpecial(thunk.getSymbol());// should restore to default function
			}

			assertEquals("Name1", thunk.getName());
			assertEquals(SourceType.DEFAULT, thunk.getSymbol().getSource());

			thunkedFunc.setName("Name2", SourceType.USER_DEFINED);
			assertEquals("Name2", thunkedFunc.getName());

			if (isDefault) {
				finalName = "Name2";
			}
			else {
				thunk.setName(origThunkName, SourceType.USER_DEFINED);
				finalName = origThunkName;
			}

			thunkedFunc.setCustomVariableStorage(true);

			thunkedFunc.insertParameter(0,
				new ParameterImpl("param_1",
					IntegerDataType.dataType.clone(program.getDataTypeManager()),
					program.getRegister("EAX"), program),
				SourceType.DEFAULT);

			thunk.insertParameter(1,
				new ParameterImpl("param_2",
					Undefined4DataType.dataType.clone(program.getDataTypeManager()),
					program.getRegister("ECX"), program),
				SourceType.DEFAULT);
		}
		finally {
			program.endTransaction(txId, true);
		}
		program.flushEvents();

		Address thunkAddr = thunk.getEntryPoint();
		assertTrue(cb.goToField(thunkAddr, "Variable Location", 1, 0, 0));
		assertEquals("EAX:4", cb.getCurrentFieldText());
		assertTrue(cb.goToField(thunkAddr, "Variable Location", 2, 0, 0));
		assertEquals("ECX:4", cb.getCurrentFieldText());

		cb.goToField(thunkAddr, "Function Signature", 0, 0);
		assertEquals("thunk undefined " + finalName + "(int param_1, undefined4 param_2)",
			cb.getCurrentFieldText());

		txId = program.startTransaction("Add params");
		try {
			// restore name
			thunkedFunc.setName(origThunkedName, SourceType.USER_DEFINED);
			assertEquals(origThunkedName, thunkedFunc.getName());
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private Function createThunk(Address thunkEntry, final String refFunc, boolean expectedDefault)
			throws Exception {

		deleteExistingFunction(thunkEntry);

		assertTrue(cb.goToField(thunkEntry, "Address", 0, 0));

		performAction(createThunk, cb.getProvider(), false);

		ThunkReferenceAddressDialog thunkDialog =
			waitForDialogComponent(null, ThunkReferenceAddressDialog.class, 100);
		assertNotNull(thunkDialog);
		JTextField thunkedEntryField = findComponent(thunkDialog, JTextField.class);
		assertEquals(expectedDefault ? refFunc : "", thunkedEntryField.getText());
		runSwing(() -> {
			thunkedEntryField.setText(refFunc);
			pressButtonByText(thunkDialog, "OK");
		});
		waitForSwing();
		waitForBusyTool();

		Function thunk = program.getListing().getFunctionAt(thunkEntry);
		assertNotNull(thunk);
		assertTrue(thunk.isThunk());
		return thunk;
	}

	private void deleteExistingFunction(Address entry) {
		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		if (f == null) {
			return;
		}

		assertTrue(applyCmd(program, new DeleteFunctionCmd(entry)));
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(NextPrevSelectedRangePlugin.class.getName());
		tool.addPlugin(NextPrevHighlightRangePlugin.class.getName());
		tool.addPlugin(SetHighlightPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());
		tool.addPlugin(AutoAnalysisPlugin.class.getName());
		tool.addPlugin(DisassemblerPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);
		dp = getPlugin(tool, DisassemblerPlugin.class);

		fp = getPlugin(tool, FunctionPlugin.class);
		createFunction = getAction(fp, "Create Function");
		createThunk = getAction(fp, "Create Thunk Function");
		editThunk = getAction(fp, "Set Thunked Function");
		revertThunk = getAction(fp, "Revert Thunk Function");
		deleteFunction = getAction(fp, "Delete Function");
		editComment = getAction(fp, "Edit Variable Comment");
		deleteComment = getAction(fp, "Delete Function Variable Comment");
		byteCycleAction = getAction(fp, "Cycle: byte,word,dword,qword");
		floatCycleAction = getAction(fp, "Cycle: float,double");
		createArray = getAction(fp, "Define Array");
		createPointer = getAction(fp, "Define pointer");
		clearFunctionReturnTypeAction = getAction(fp, "Clear Function Return Type");
		deleteFunctionVar = getAction(fp, "Delete Function Variable");
		chooseDataType = getAction(fp, "Choose Data Type");
	}

	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram(program, true);
		waitForSwing();
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private Function createAFunction() throws Exception {

		FunctionManager fm = program.getFunctionManager();
		Function function = fm.getFunctionAt(cb.getCurrentAddress());
		if (function != null) {
			return function;
		}

		performAction(createFunction, cb.getProvider(), false);

		//		FunctionNameDialog d = (FunctionNameDialog)waitForDialogComponent(tool.getToolFrame(),
		//		FunctionNameDialog.class, 2000);
		//assertNotNull(d);
		//pressButtonByText(d, "OK");

		waitForBusyTool();

		// cheat setting custom storage since we are not testing the edit function dialog here
		Address addr = cb.getCurrentAddress();
		function = program.getListing().getFunctionAt(addr);
		assertNotNull(function);

		program.flushEvents();
		waitForSwing();

		waitForBusyTool();

		cb.updateNow();

		return function;
	}

	private void setCustomParameterStorage(Function function, boolean enabled) {
		int txId = program.startTransaction("Set Custom Storage");
		try {
			function.setCustomVariableStorage(enabled);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private void waitForBusyTool() {
		waitForBusyTool(tool);
		program.flushEvents();
		waitForSwing();
		cb.updateNow();
	}

	private void doCycleAction(DockingActionIf action) {
		assertTrue(action.isEnabledForContext(cb.getProvider().getActionContext(null)));
		performAction(action, cb.getProvider(), true);
		program.flushEvents();
		waitForSwing();
		cb.updateNow();
	}

	private Function createFunctionAtEntry() {
		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(addr("0x1006420"));
		if (f != null) {
			// we want to recreate the function, to get better analysis
			deleteExistingFunction(f.getEntryPoint());
		}

		return createFunctionAt("0x1006420");
	}

	private Function createFunctionAt(String addrString) {

		Address addr = addr(addrString);

		cb.goToField(addr, "Address", 0, 0);

		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(addr);
		if (f != null) {
			// we want to recreate the function, to get better analysis
			deleteExistingFunction(f.getEntryPoint());
		}

		performAction(createFunction, cb.getProvider().getActionContext(null), true);
		waitForBusyTool();
		cb.goToField(addr, "Function Signature", 0, 0);

		f = fm.getFunctionAt(addr);
		assertNotNull(f);
		return f;
	}

	private void loadProgram(String programName) throws Exception {

		if ("notepad".equals(programName)) {
			ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
			program = builder.getProgram();

			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
			builder.dispose();
			waitForSwing();
			addrFactory = program.getAddressFactory();
		}
		else {
			Assert.fail("don't have program: " + programName);
		}
	}

	private Function getFunction(String name) {
		List<Function> functions = program.getListing().getGlobalFunctions(name);
		assertEquals(1, functions.size());
		return functions.get(0);
	}
}
