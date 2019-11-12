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
package ghidra.app.plugin.core.stackeditor;

import static org.junit.Assert.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;

import org.junit.*;

import docking.action.DockingAction;
import docking.action.DockingActionIf;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.analysis.AutoAnalysisPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.compositeeditor.*;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;

public abstract class AbstractStackEditorTest extends AbstractEditorTest {

	FunctionPlugin functionPlugin;
	CodeBrowserPlugin cb;
	protected AddressFactory addrFactory;
	protected AutoAnalysisPlugin autoAnalysisPlugin;
	protected StackEditorManagerPlugin stackEditorMgr;
	Function function;
	StackFrame stackFrame;
	StackFrame emptyPosStack;
	StackFrame emptyNegStack;
	StackFrame simplePosStack;
	StackFrame simpleNegStack;
	protected StackEditorModel stackModel;
	protected static final int ORIGINAL_STACK = 0;
	protected static final int EMPTY_STACK = 1;
	protected static final int NO_VAR_STACK = 2;
	protected static final int SIMPLE_STACK = 3;

	DockingActionIf createFunctionAction;
	DockingActionIf analyzeStackAction;
	DockingActionIf deleteFunctionAction;
	DockingActionIf editStackAction;

	// Editor Actions
	ApplyAction applyAction;
	ArrayAction arrayAction;
	ClearAction clearAction;
	DeleteAction deleteAction;
	DockingAction closeAction;
	EditComponentAction editComponentAction;
	EditFieldAction editFieldAction;
	PointerAction pointerAction;
	ShowComponentPathAction showComponentPathAction;
	HexNumbersAction hexNumbersAction;

	private final boolean positiveStack;

	public AbstractStackEditorTest(boolean positiveStack) {
		super();
		this.positiveStack = positiveStack;
		compilerSpecID = positiveStack ? "posStack" : "default";
		languageName = languageName.replace("default", compilerSpecID);
	}

	StackEditorModel getModel() {
		return (StackEditorModel) model;
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		addrFactory = program.getAddressFactory();

		builder.createMemory("bk1", "0100", 0x200);
		function = builder.createEmptyFunction("entry", null, "__stackcall", "0100", 10,
			ByteDataType.dataType, ByteDataType.dataType, WordDataType.dataType,
			DWordDataType.dataType);

		int transaction = program.startTransaction("test");
		try {
			int stackOffset = positiveStack ? 0 : -4;
			int stackChange = positiveStack ? 4 : -4;
			for (int i = 0; i < 4; i++) {
				function.addLocalVariable(
					new LocalVariableImpl(null, DWordDataType.dataType, stackOffset, program),
					SourceType.DEFAULT);
				stackOffset += stackChange;
			}
		}
		finally {
			program.endTransaction(transaction, true);
		}

		setCustomVariableStorage(true);
		stackFrame = function.getStackFrame();
	}

	protected void setCustomVariableStorage(boolean useCustomStorage) {
		int transaction = program.startTransaction(
			(useCustomStorage ? "Enable" : "Disable") + " Custom Variable Storage");
		try {
			function.setCustomVariableStorage(useCustomStorage);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	@Override
	@After
	public void tearDown() throws Exception {
		cancelEditing();

		super.tearDown();

		closeAllWindows();
	}

	private void cancelEditing() {
		if (provider == null) {
			return;
		}

		Object editorPanel = getInstanceField("editorPanel", provider);
		final JTable table = (JTable) getInstanceField("table", editorPanel);
		runSwing(() -> table.editingCanceled(new ChangeEvent(table)));
		waitForPostedSwingRunnables();// some editing notifications are in an invokeLater
	}

	@Override
	protected void setUpPlugins() throws PluginException {
		super.setUpPlugins();

		tool.addPlugin(AutoAnalysisPlugin.class.getName());
		tool.addPlugin(StackEditorManagerPlugin.class.getName());

		stackEditorMgr = getPlugin(tool, StackEditorManagerPlugin.class);

		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());
		tool.addPlugin(AutoAnalysisPlugin.class.getName());

		cb = getPlugin(tool, CodeBrowserPlugin.class);
		functionPlugin = getPlugin(tool, FunctionPlugin.class);
		autoAnalysisPlugin = getPlugin(tool, AutoAnalysisPlugin.class);

		createFunctionAction = getAction(functionPlugin, "Create Function");
		analyzeStackAction = getAction(functionPlugin, "Analyze Function Stack References");
		deleteFunctionAction = getAction(functionPlugin, "Delete Function");
		editStackAction = getAction(stackEditorMgr, "Edit Stack Frame");
	}

	protected void init(int stack) throws Exception {
		boolean changed = false;
		try {
			startTransaction("Setup Test \"sscanf\" Stack Frame Variables");
			switch (stack) {
				case EMPTY_STACK:
					clearStack();
					stackFrame.setLocalSize(0);
					//stackFrame.setParameterOffset(0);
					changed = true;
					break;
				case NO_VAR_STACK:
					clearStack();
					changed = true;
					break;
				case SIMPLE_STACK:
					clearStack();
					if (positiveStack) {
						stackFrame.createVariable(null, -10, new WordDataType(),
							SourceType.USER_DEFINED);
						stackFrame.createVariable("MyFloatParam", 14, new FloatDataType(),
							SourceType.USER_DEFINED);
						stackFrame.createVariable(null, 4, new Pointer32DataType(),
							SourceType.USER_DEFINED);
						stackFrame.createVariable(null, -8, DataType.DEFAULT,
							SourceType.USER_DEFINED);
						stackFrame.createVariable(null, -14, new Undefined4DataType(),
							SourceType.USER_DEFINED);
					}
					else {
						stackFrame.createVariable(null, 8, new WordDataType(),
							SourceType.USER_DEFINED);
						stackFrame.createVariable("MyFloatParam", 10, new FloatDataType(),
							SourceType.USER_DEFINED);
						stackFrame.createVariable(null, -8, new Pointer32DataType(),
							SourceType.USER_DEFINED);
						stackFrame.createVariable(null, -12, DataType.DEFAULT,
							SourceType.USER_DEFINED);
						stackFrame.createVariable(null, -16, new Undefined4DataType(),
							SourceType.USER_DEFINED);
					}
					changed = true;
					break;
				case ORIGINAL_STACK:
				default:
					break;
			}
		}
		finally {
			endTransaction(changed);
		}
		if (provider != null) {
			Assert.fail("Provider initialized more than once -- stop it!");
		}
		runSwing(() -> {
			installProvider(new StackEditorProvider(stackEditorMgr, stackFrame.getFunction()));
			assertNotNull(provider);
			model = ((StackEditorProvider) provider).getModel();
		});
		waitForPostedSwingRunnables();
//		assertTrue(!model.isLocked());
		getActions();
		stackModel = (StackEditorModel) model;
	}

	private void clearStack() {
		Variable[] vars = stackFrame.getStackVariables();
		for (Variable element : vars) {
			stackFrame.clearVariable(element.getStackOffset());
		}
	}

	protected void cleanup() {
		clearActions();

		Object editorPanel = getInstanceField("editorPanel", provider);
		final JTable table = (JTable) getInstanceField("table", editorPanel);
		runSwing(() -> table.editingCanceled(new ChangeEvent(table)));
		waitForPostedSwingRunnables();// some editing notifications are in an invokeLater

		runSwing(() -> provider.dispose(), true);
	}

	void clearActions() {
		actions = null;
		favorites.clear();
		cycles.clear();
		applyAction = null;
		arrayAction = null;
		deleteAction = null;
		closeAction = null;
		editComponentAction = null;
		editFieldAction = null;
		pointerAction = null;
		showComponentPathAction = null;
		hexNumbersAction = null;
	}

	void getActions() {
		actions = ((StackEditorProvider) provider).getActions();
		for (CompositeEditorTableAction element : actions) {
			if (element instanceof FavoritesAction) {
				favorites.add((FavoritesAction) element);
			}
			else if (element instanceof CycleGroupAction) {
				cycles.add((CycleGroupAction) element);
			}
			else if (element instanceof ApplyAction) {
				applyAction = (ApplyAction) element;
			}
			else if (element instanceof ArrayAction) {
				arrayAction = (ArrayAction) element;
			}
			else if (element instanceof DeleteAction) {
				deleteAction = (DeleteAction) element;
			}
			else if (element instanceof ClearAction) {
				clearAction = (ClearAction) element;
			}
			else if (element instanceof EditComponentAction) {
				editComponentAction = (EditComponentAction) element;
			}
			else if (element instanceof EditFieldAction) {
				editFieldAction = (EditFieldAction) element;
			}
			else if (element instanceof PointerAction) {
				pointerAction = (PointerAction) element;
			}
			else if (element instanceof ShowComponentPathAction) {
				showComponentPathAction = (ShowComponentPathAction) element;
			}
			else if (element instanceof HexNumbersAction) {
				hexNumbersAction = (HexNumbersAction) element;
			}
		}
	}

	int getOrdinalAtOffset(int offset) {
		DataTypeComponent dtc = stackModel.getEditorStack().getComponentAt(offset);
		if (dtc != null) {
			return dtc.getOrdinal();
		}
		return -1;
	}

	protected void setField(final JTextField field, String value) {
		assertNotNull(field);
		setText(field, value);
		triggerEnter(field);
	}

	Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	void setLocation(String address) {
		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr(address)), program));
		assertEquals(addr(address), cb.getCurrentAddress());
	}

	void createFunction(String address) throws Exception {
		setLocation(address);
		builder.createEmptyFunction(null, address, 100, null, (Parameter[]) null);
		waitForBusyTool(tool);
	}

	void analyzeStack(String address) {
		setLocation(address);
		DockingActionIf analyzeStack =
			getAction(functionPlugin, "Analyze Function Stack References");
		performAction(analyzeStack, cb.getProvider(), true);
		waitForBusyTool(tool);
	}

	void editStack(String address) {
		setLocation(address);
		DockingActionIf editStack = getAction(stackEditorMgr, "Edit Stack Frame");
		performAction(editStack, cb.getProvider(), true);
		waitForBusyTool(tool);

		Function f = program.getFunctionManager().getFunctionAt(addr(address));
		String funcName = f.getName();
		assertTrue(isProviderShown(tool.getToolFrame(), "Stack Editor",
			StackEditorProvider.getProviderSubTitle(f)));
		installProvider(stackEditorMgr.getProvider(program, funcName));

		model = ((StackEditorProvider) provider).getModel();
		stackModel = (StackEditorModel) model;
		assertNotNull(model);
		getActions();
	}

	void closeEditor() {
		SwingUtilities.invokeLater(() -> provider.closeComponent());
		waitForPostedSwingRunnables();
	}
}
