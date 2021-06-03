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
package ghidra.app.plugin.core.clipboard;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.FocusListener;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.*;
import java.util.List;

import javax.swing.*;

import org.junit.*;

import docking.*;
import docking.action.*;
import docking.dnd.GClipboard;
import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldSelection;
import generic.test.TestUtils;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.byteviewer.*;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.decompile.DecompilerClipboardProvider;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.format.ByteBlockSelection;
import ghidra.app.plugin.core.format.DataFormatModel;
import ghidra.app.plugin.core.functiongraph.FGClipboardProvider;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.util.ByteCopier;
import ghidra.app.util.viewer.field.LabelFieldFactory;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.*;
import ghidra.util.Msg;

/**
 *
 * 			Note: This test is sensitive to focus. So, don't click any windows while this test
 *                is running.
 *
 */

public class ClipboardPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String COPY_ACTION_NAME = "Copy";
	private static final String PASTE_ACTION_NAME = "Paste";
	private static final String COPY_SPECIAL_ACTION_NAME = "Copy Special";
	private static final Transferable DUMMY_TRANSFERABLE = new DummyTransferable();

	private PluginTool tool;
	private TestEnv env;
	private Program program;
	private Map<ClipboardContentProviderService, List<DockingAction>> actionMap;
	private ByteViewerClipboardProvider byteViewerClipboardProvider;
	private DecompilerClipboardProvider decompileClipboardProvider;
	private CodeBrowserClipboardProvider codeBrowserClipboardProvider;
	private CodeBrowserPlugin codeBrowserPlugin;
	private ByteViewerPlugin byteViewerPlugin;
	private CodeViewerProvider codeViewerProvider;
	private ClipboardPlugin clipboardPlugin;
	private ComponentProvider decompileProvider;
	private ComponentProviderWrapper codeViewerWrapper;
	private ComponentProviderWrapper byteViewerWrapper;
	private ComponentProviderWrapper decompilerWrapper;

	@Before
	public void setUp() throws Exception {

		String name = super.testName.getMethodName();
		if (name.endsWith("_Notepad")) {
			program = createNotepadProgram();
		}
		else {
			program = createDefaultProgram();
		}

		env = new TestEnv();
		setErrorGUIEnabled(false);
		tool = env.launchDefaultTool(program);

		waitForBusyTool(tool);
		waitForSwing();

		// get actions for each service provider
		clipboardPlugin = getPlugin(tool, ClipboardPlugin.class);
		actionMap = getActionMap();

		// Showing decompiler establishes clipboard provider for it
		initializeComponentProviders();

		initializeClipboardProviders();

		clearClipboardContents();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private Program createDefaultProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("default", ProgramBuilder._TOY, this);

		builder.createMemory("test", "0x01001050", 20000);

		builder.setBytes("0x01001050",
			"0e 5e f4 77 33 58 f4 77 91 45 f4 77 88 7c f4 77 8d 70 f5 77 05 62 f4 77 f0 a3 " +
				"f4 77 09 56 f4 77 10 17 f4 77 f7 29 f6 77 02 59 f4 77");

		builder.createMemoryReference("0x01002cc0", "0x01002cf0", RefType.DATA,
			SourceType.USER_DEFINED);
		builder.createMemoryReference("0x01002d04", "0x01002d0f", RefType.DATA,
			SourceType.USER_DEFINED);

		DataType dt = DataType.DEFAULT;
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction("ghidra", "0x01002cf5", 1, dt, p);
		builder.createEmptyFunction("sscanf", "0x0100415a", 1, dt, p);

		builder.createComment("0x0100415a",
			"\n;|||||||||||||||||||| FUNCTION ||||||||||||||||||||||||||||||||||||||||||||||||||\n ",
			CodeUnit.PLATE_COMMENT);

		builder.setBytes("0x0100418c", "ff 15 08 10 00 01");
		builder.disassemble("0x0100418c", 6);

		return builder.getProgram();
	}

	private Program createNotepadProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("notepad", false, this);

		// need a default label at 01002cf0, so make up a reference
		builder.createMemoryReference("01002ce5", "01002cf0", RefType.FALL_THROUGH,
			SourceType.ANALYSIS);

		return builder.getProgram();
	}

	@SuppressWarnings("unchecked")
	private Map<ClipboardContentProviderService, List<DockingAction>> getActionMap() {
		return (Map<ClipboardContentProviderService, List<DockingAction>>) getInstanceField(
			"serviceActionMap", clipboardPlugin);
	}

	private void initializeClipboardProviders() {
		Map<ClipboardContentProviderService, List<DockingAction>> serviceMap = getActionMap();
		Set<ClipboardContentProviderService> services = serviceMap.keySet();
		for (Object object : services) {
			if (object instanceof ByteViewerClipboardProvider) {
				byteViewerClipboardProvider = (ByteViewerClipboardProvider) object;
			}
			else if (object instanceof CodeBrowserClipboardProvider &&
				!(object instanceof FGClipboardProvider)) {
				codeBrowserClipboardProvider = (CodeBrowserClipboardProvider) object;
			}
			else if (object instanceof DecompilerClipboardProvider) {
				decompileClipboardProvider = (DecompilerClipboardProvider) object;
			}
		}
	}

	private void initializeComponentProviders() {
		codeBrowserPlugin = getPlugin(tool, CodeBrowserPlugin.class);
		codeViewerProvider =
			(CodeViewerProvider) invokeInstanceMethod("getProvider", codeBrowserPlugin);
		codeViewerWrapper = new CodeViewerWrapper(codeViewerProvider);
		tool.showComponentProvider(codeViewerProvider, true);

		ComponentProvider decompiler = tool.getComponentProvider("Decompiler");
		tool.showComponentProvider(decompiler, true);

		waitForSwing();
		byteViewerPlugin = getPlugin(tool, ByteViewerPlugin.class);
		ComponentProvider provider =
			(ComponentProvider) getInstanceField("connectedProvider", byteViewerPlugin);
		byteViewerWrapper = new ByteViewerWrapper(provider);
		tool.showComponentProvider(provider, true);
		setByteViewerEditable(false);

		decompileProvider = waitForComponentProvider(DecompilerProvider.class);
		decompilerWrapper = new DecompilerWrapper(decompileProvider);

		waitForSwing();
	}

	private DockingAction getAction(ClipboardContentProviderService service, String actionName) {
		List<DockingAction> list = actionMap.get(service);
		for (DockingAction pluginAction : list) {
			if (pluginAction.getName().equals(actionName)) {
				return pluginAction;
			}
		}
		return null;
	}

	private Address addr(String address) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getAddress(address);
	}

	private void renameLabel(ProgramLocation location, String oldName, String newName) {
		RenameLabelCmd cmd =
			new RenameLabelCmd(location.getAddress(), oldName, newName, SourceType.USER_DEFINED);
		assertTrue(applyCmd(program, cmd));
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol currentSymbol = symbolTable.getPrimarySymbol(location.getAddress());
		assertEquals(newName, currentSymbol.getName());
	}

	@Test
	public void testCodeBrowser_CopyFromLabel_PasteToLabel() throws Exception {
		//
		// Test that we can copy (simulating the keyboard action) from one label and then
		// paste onto another label.  This is useful for copying across programs, as doing so
		// in the same program will fail due to a name collision.  So, we have to perform the
		// following steps to test the code:
		// 1) Name a label to a custom name
		// 2) Put the cursor on that label and execute the copy command (to get the name on the clipboard)
		// 3) Perform an undo to remove the custom name we created
		// 4) Put the cursor on a different label and execute the paste command
		//

		String oldLabelName = "DAT_01002cf0";
		LabelFieldLocation location =
			new LabelFieldLocation(program, addr("01002cf0"), oldLabelName, null, 0);
		codeBrowserPlugin.goTo(location);

		// 1)
		String newLabelName = "BigBuddyBob";
		renameLabel(location, oldLabelName, newLabelName);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof LabelFieldLocation);
		location = (LabelFieldLocation) currentLocation;
		assertTrue(newLabelName.equals(location.getName()));

		assertTrue(codeBrowserClipboardProvider.canCopy());

		// 2)
		DockingAction copyAction = getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		ActionContext context = codeViewerProvider.getActionContext(null);
		performAction(copyAction, context, true);

		// 3)
		undo(program);

		// 4)
		LabelFieldLocation newLabelLocation =
			new LabelFieldLocation(program, addr("01002d0f"), "DAT_01002d0f", null, 0);
		codeBrowserPlugin.goTo(newLabelLocation);

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		performAction(pasteAction, context, true);
		waitForBusyTool(tool);

		currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof LabelFieldLocation);
		location = (LabelFieldLocation) currentLocation;
		Msg.debug(this, "checking name!: " + location);
		assertEquals(newLabelName, location.getName());
	}

	@Test
	public void testCodeBrowser_CopyFromLabel_PasteToFunction() throws Exception {
		//
		// Test that we can copy (simulating the keyboard action) from one label and then
		// paste onto a function.  This is useful for copying across programs, as doing so
		// in the same program will fail due to a name collision.  So, we have to perform the
		// following steps to test the code:
		// 1) Name a label to a custom name
		// 2) Put the cursor on that label and execute the copy command (to get the name on the clipboard)
		// 3) Perform an undo to remove the custom name we created
		// 4) Put the cursor on a different label and execute the paste command
		//

		String oldLabelName = "DAT_01002cf0";
		LabelFieldLocation location =
			new LabelFieldLocation(program, addr("01002cf0"), oldLabelName, null, 0);
		codeBrowserPlugin.goTo(location);

		// 1)
		String newLabelName = "BigBuddyBob";
		renameLabel(location, oldLabelName, newLabelName);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof LabelFieldLocation);
		location = (LabelFieldLocation) currentLocation;
		assertTrue(newLabelName.equals(location.getName()));

		assertTrue(codeBrowserClipboardProvider.canCopy());

		// 2)
		DockingAction copyAction = getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		ActionContext context = codeViewerProvider.getActionContext(null);
		performAction(copyAction, context, true);

		// 3)
		undo(program);

		// 4)
		FunctionNameFieldLocation functionLocation =
			new FunctionNameFieldLocation(program, addr("01002cf5"), "ghidra");
		codeBrowserPlugin.goTo(functionLocation);

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		performAction(pasteAction, context, true);
		waitForBusyTool(tool);

		currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof FunctionNameFieldLocation);
		functionLocation = (FunctionNameFieldLocation) currentLocation;
		assertEquals(newLabelName, functionLocation.getFunctionName());
	}

	@Test
	public void testCodeBrowser_CopyFromLabel_PasteToComment() throws Exception {
		//
		// Test that we can copy (simulating the keyboard action) from a label and then
		// paste onto a comment.
		//

		String oldLabelName = "DAT_01002cf0";
		LabelFieldLocation location =
			new LabelFieldLocation(program, addr("01002cf0"), oldLabelName, null, 0);
		codeBrowserPlugin.goTo(location);

		// 1)
		String newLabelName = "BigBuddyBob";
		renameLabel(location, oldLabelName, newLabelName);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof LabelFieldLocation);
		location = (LabelFieldLocation) currentLocation;
		assertTrue(newLabelName.equals(location.getName()));

		assertTrue(codeBrowserClipboardProvider.canCopy());

		// 2)
		DockingAction copyAction = getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		ActionContext context = codeViewerProvider.getActionContext(null);
		performAction(copyAction, context, true);

		// 3)
		PlateFieldLocation plateFieldLocation =
			new PlateFieldLocation(program, addr("0100415a"), null, 1, 10, new String[] { "" }, 0);

		codeBrowserPlugin.goTo(plateFieldLocation);

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		performAction(pasteAction, context, true);
		waitForBusyTool(tool);

		currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof PlateFieldLocation);
		plateFieldLocation = (PlateFieldLocation) currentLocation;
		String[] comments = plateFieldLocation.getComment();
		assertEquals(1, comments.length);
		assertEquals(newLabelName, comments[0]);
	}

	@Test
	public void testCodeBrowser_CopyFromLabel_PasteToVariable_Notepad() throws Exception {
		//
		// Test that we can copy (simulating the keyboard action) from one label and then
		// paste onto a variable.  This is useful for copying across programs, as doing so
		// in the same program will fail due to a name collision.
		//
		// So, we have to perform the following steps to test the code:
		// 1) Name a label to a custom name
		// 2) Put the cursor on that label and execute the copy command (to get the name on the clipboard)
		// 3) Perform an undo to remove the custom name we created
		// 4) Put the cursor on a different label and execute the paste command
		//

		String oldLabelName = "LAB_01002cf0";
		LabelFieldLocation location =
			new LabelFieldLocation(program, addr("01002cf0"), oldLabelName, null, 0);
		codeBrowserPlugin.goTo(location);

		// 1)
		String newLabelName = "BigBuddyBob";
		renameLabel(location, oldLabelName, newLabelName);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof LabelFieldLocation);
		location = (LabelFieldLocation) currentLocation;
		assertTrue(newLabelName.equals(location.getName()));

		assertTrue(codeBrowserClipboardProvider.canCopy());

		// 2)
		DockingAction copyAction = getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		ActionContext context = codeViewerProvider.getActionContext(null);
		performAction(copyAction, context, true);

		// 3)
		undo(program);

		// 4)
		String operandPrefix = "dword ptr [EBP + ";
		String operandReferenceName = "destStr]";
		OperandFieldLocation variableOperandReferenceLocation = new OperandFieldLocation(program,
			addr("0100416c"), null, addr("0x8"), operandPrefix + operandReferenceName, 1, 9);
		codeBrowserPlugin.goTo(variableOperandReferenceLocation);

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		performAction(pasteAction, context, true);

		currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof OperandFieldLocation);
		variableOperandReferenceLocation = (OperandFieldLocation) currentLocation;
		assertEquals(operandPrefix + newLabelName + "]",
			variableOperandReferenceLocation.getOperandRepresentation());
	}

	@Test
	public void testCodeBrowser_CopyFromOperandReference_PasteToLabel_Notepad() throws Exception {
		//
		// Test that we can copy (simulating the keyboard action) from an operand reference
		// label and then paste onto another label.  This is useful for copying across
		// programs, as doing so in the same program will fail due to a name
		// collision.

		// So, we have to perform the following steps to test the code:
		// 1) Put the cursor on an operand and execute the copy command (to get the name on the clipboard)
		// 2) Name that operand's label to a custom name
		// 3) Put the cursor on a different label and execute the paste command
		//

		// 1)
		String operandText = "dword ptr [->ADVAPI32.dll::RegQueryValueExW]";
		OperandFieldLocation operandFieldLocation = new OperandFieldLocation(program,
			addr("0100418c"), null, addr("01001008"), operandText, 15, 0);
		codeBrowserPlugin.goTo(operandFieldLocation);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof OperandFieldLocation);
		operandFieldLocation = (OperandFieldLocation) currentLocation;
		assertEquals(operandText, operandFieldLocation.getOperandRepresentation());

		assertTrue(codeBrowserClipboardProvider.canCopy());

		DockingAction copyAction = getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		ActionContext context = codeViewerProvider.getActionContext(null);
		performAction(copyAction, context, true);

		// 2)
		String oldLabelName = "ADVAPI32.dll_RegQueryValueExW";
		LabelFieldLocation renameLabelLocation =
			new LabelFieldLocation(program, addr("01001008"), oldLabelName, null, 0);
		codeBrowserPlugin.goTo(renameLabelLocation);

		String newLabelName = "BigBuddyBob";
		renameLabel(renameLabelLocation, oldLabelName, newLabelName);

		// 3)
		String oldPasteName = "LAB_01002cf0";
		LabelFieldLocation pasteLabelLocation =
			new LabelFieldLocation(program, addr("01002cf0"), oldPasteName, null, 0);
		assertTrue(
			codeBrowserPlugin.goToField(addr("01002cf0"), LabelFieldFactory.FIELD_NAME, 0, 0));

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		performAction(pasteAction, context, true);
		waitForBusyTool(tool);

		currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof LabelFieldLocation);
		pasteLabelLocation = (LabelFieldLocation) currentLocation;
		assertEquals(oldLabelName, pasteLabelLocation.getName());
	}

	@Test
	public void testCodeBrowser_CopyFromFunction_PasteToLabel() throws Exception {
		//
		// Test that we can copy (simulating the keyboard action) from one function label and then
		// paste onto another label.  This is useful for copying across programs, as doing so
		// in the same program will fail due to a name collision.  So, we have to perform the
		// following steps to test the code:
		// 1) Name a label to a custom name
		// 2) Put the cursor on that label and execute the copy command (to get the name on the clipboard)
		// 3) Perform an undo to remove the custom name we created
		// 4) Put the cursor on a different label and execute the paste command
		//

		String functionName = "sscanf";
		FunctionNameFieldLocation location =
			new FunctionNameFieldLocation(program, addr("0100415a"), functionName);
		codeBrowserPlugin.goTo(location);

		// 1)
		String newLabelName = "BigBuddyBob";
		renameLabel(location, functionName, newLabelName);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof FunctionNameFieldLocation);
		location = (FunctionNameFieldLocation) currentLocation;
		assertTrue(newLabelName.equals(location.getFunctionName()));

		assertTrue(codeBrowserClipboardProvider.canCopy());

		// 2)
		DockingAction copyAction = getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		ActionContext context = codeViewerProvider.getActionContext(null);
		performAction(copyAction, context, true);
		assertEquals(newLabelName, getClipboardContents());

		// 3)
		undo(program);

		// 4)
		LabelFieldLocation newLabelLocation =
			new LabelFieldLocation(program, addr("01002d0f"), "DAT_01002d0f", null, 0);
		codeBrowserPlugin.goTo(newLabelLocation);

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		performAction(pasteAction, context, true);
		waitForBusyTool(tool);

		currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof LabelFieldLocation);
		LabelFieldLocation labelLocation = (LabelFieldLocation) currentLocation;
		assertEquals(newLabelName, labelLocation.getName());
	}

	@Test
	public void testCodeBrowser_CopyFromFunction_PasteToComment() throws Exception {
		//
		// Test that we can copy (simulating the keyboard action) from a function and then
		// paste onto a comment.
		//

		// 1)
		String functionName = "sscanf";
		FunctionNameFieldLocation location =
			new FunctionNameFieldLocation(program, addr("0100415a"), functionName);
		codeBrowserPlugin.goTo(location);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof FunctionNameFieldLocation);
		location = (FunctionNameFieldLocation) currentLocation;
		assertTrue(functionName.equals(location.getFunctionName()));

		assertTrue(codeBrowserClipboardProvider.canCopy());

		// 2)
		DockingAction copyAction = getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		ActionContext context = codeViewerProvider.getActionContext(null);
		performAction(copyAction, context, true);

		// 3)
		PlateFieldLocation plateFieldLocation =
			new PlateFieldLocation(program, addr("0100415a"), null, 1, 10, new String[] { "" }, 0);

		codeBrowserPlugin.goTo(plateFieldLocation);

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		performAction(pasteAction, context, true);

		currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof PlateFieldLocation);
		plateFieldLocation = (PlateFieldLocation) currentLocation;
		String[] comments = plateFieldLocation.getComment();
		assertEquals(1, comments.length);
		assertEquals(functionName, comments[0]);
	}

	@Test
	public void testCodeBrowser_CopyFromComment_PasteToComment() throws Exception {
		//
		// Test that we can copy (simulating the keyboard action) from one comment and then
		// paste onto another comment.
		//

		PlateFieldLocation plateFieldLocation =
			new PlateFieldLocation(program, addr("0100415a"), null, 1, 10, new String[] { "" }, 0);

		codeBrowserPlugin.goTo(plateFieldLocation);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof PlateFieldLocation);
		plateFieldLocation = (PlateFieldLocation) currentLocation;
		String commentText = plateFieldLocation.getComment()[1];
		assertEquals(
			";|||||||||||||||||||| FUNCTION ||||||||||||||||||||||||||||||||||||||||||||||||||",
			commentText);

		assertTrue(codeBrowserClipboardProvider.canCopy());

		// 2)
		DockingAction copyAction = getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		ActionContext context = codeViewerProvider.getActionContext(null);
		performAction(copyAction, context, true);

		// 3)
		// 0100415a PreCommentFieldLocation
		CommentFieldLocation commentFieldLocation = new CommentFieldLocation(program,
			addr("0100415a"), null, new String[] { "" }, CodeUnit.PRE_COMMENT, 5, 10);

		codeBrowserPlugin.goTo(plateFieldLocation);

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		performAction(pasteAction, context, true);
		waitForBusyTool(tool);

		currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof CommentFieldLocation);
		commentFieldLocation = (CommentFieldLocation) currentLocation;
		String[] comments = commentFieldLocation.getComment();
		assertEquals(2, comments.length);
		assertEquals(commentText, comments[0]);
	}

	@Test
	public void testCodeBrowser_CopySpecial_WithSelection() throws Exception {

		DockingAction copySpecialAction =
			getAction(codeBrowserClipboardProvider, COPY_SPECIAL_ACTION_NAME);
		waitForSwing();
		assertFalse(copySpecialAction.isEnabled());

		codeBrowserPlugin.goTo(new MnemonicFieldLocation(program, addr("1001050")));
		assertTrue(copySpecialAction.isEnabled());

		makeSelection(codeViewerWrapper);
		assertTrue(copySpecialAction.isEnabled());

		copySpecial(codeViewerWrapper, copySpecialAction);
		String clipboardContents = getClipboardContents();
		String expectedBytes = "f4 77 33 58 f4 77 91 45";
		assertEquals(expectedBytes, clipboardContents);
	}

	@Test
	public void testCodeBrowser_CopySpecial_WithoutSelection() throws Exception {

		DockingAction copySpecialAction =
			getAction(codeBrowserClipboardProvider, COPY_SPECIAL_ACTION_NAME);
		waitForSwing();
		assertFalse(copySpecialAction.isEnabled());

		codeBrowserPlugin.goTo(new MnemonicFieldLocation(program, addr("1001050")));
		assertTrue(copySpecialAction.isEnabled());

		copySpecial(codeViewerWrapper, copySpecialAction);
		String clipboardContents = getClipboardContents();
		String expectedBytes = "0e";
		assertEquals(expectedBytes, clipboardContents);
	}

	@Test
	public void testCopyActionEnablement() {

		// no copy on by default
		DockingAction byteViewerCopyAction =
			getAction(byteViewerClipboardProvider, COPY_ACTION_NAME);
		DockingAction codeBrowserCopyAction =
			getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		DockingAction decompileCopyAction = getAction(decompileClipboardProvider, COPY_ACTION_NAME);

		waitForSwing();

		assertFalse(byteViewerCopyAction.isEnabled());
		assertFalse(codeBrowserCopyAction.isEnabled());

		// this action is enabled on any text
		// assertFalse(decompileCopyAction.isEnabled());

		// give the providers focus and check their actions state
		assertFalse(byteViewerCopyAction.isEnabled());

		// the code browser is special--make sure that it not only has focus, but that the location
		// of the cursor is not one of the 'special' copy locations
		codeBrowserPlugin.goTo(new MnemonicFieldLocation(program, addr("1001050")));
		assertTrue(codeBrowserCopyAction.isEnabled());

		// For each provider:
		// check copy on selection state
		makeSelection(byteViewerWrapper);

		// check the state
		assertTrue(byteViewerCopyAction.isEnabled());

		// clear the selection
		byteViewerWrapper.clearSelection();

		// check copy on selection state
		makeSelection(codeViewerWrapper);

		// check the state
		boolean enabled = codeBrowserCopyAction.isEnabled();
		assertTrue(enabled);

		// clear the selection
		codeViewerWrapper.clearSelection();

		// check copy on selection state
		makeSelection(decompilerWrapper);

		// check the state
		assertTrue(decompileCopyAction.isEnabled());
	}

	@Test
	public void testPasteActionEnablement() {

		DockingAction byteViewerCopyAction =
			getAction(byteViewerClipboardProvider, COPY_ACTION_NAME);
		DockingAction codeBrowserCopyAction =
			getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		DockingAction decompileCopyAction = getAction(decompileClipboardProvider, COPY_ACTION_NAME);

		// no paste on by default
		DockingAction byteViewerPasteAction =
			getAction(byteViewerClipboardProvider, PASTE_ACTION_NAME);
		DockingAction codeBrowserPasteAction =
			getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);

		assertFalse(byteViewerPasteAction.isEnabled());
		assertFalse(codeBrowserPasteAction.isEnabled());

		// For each provider make sure no paste on a selection without a copy:
		// check copy on selection state
		makeSelection(byteViewerWrapper);

		// check the state
		assertFalse(byteViewerPasteAction.isEnabled());

		// clear the selection
		byteViewerWrapper.clearSelection();

		// check copy on selection state
		codeViewerWrapper.clearSelection();

		// check the state
		assertFalse(codeBrowserPasteAction.isEnabled());

		// clear the selection
		codeViewerWrapper.clearSelection();

		// check copy on selection state
		makeSelection(decompilerWrapper);

		// clear the selection
		decompilerWrapper.clearSelection();

		// For each provider make sure paste on a selection after a copy:
		// check paste on selection state
		makeSelection(byteViewerWrapper);
		copy(byteViewerWrapper, byteViewerCopyAction);

		// check the state
		assertFalse(byteViewerPasteAction.isEnabled());
		setByteViewerEditable(true);
		assertTrue(byteViewerPasteAction.isEnabled());

		// clear the selection and clipboard
		byteViewerWrapper.clearSelection();
		clearClipboardContents();

		makeSelection(codeViewerWrapper);

		copy(codeViewerWrapper, codeBrowserCopyAction);

// TODO: if we ever find a way to prevent the paste action from being enabled without
// actually doing the paste, then the following line of code can be put back in the test
// check the state - can't paste a generic copy!
//assertTrue( !codeBrowserPasteAction.isEnabled() );

		// now perform a 'copy special' and choose a type that the paste will accept
		DockingAction codeBrowserCopySpecialAction =
			getAction(codeBrowserClipboardProvider, COPY_SPECIAL_ACTION_NAME);
		assertTrue(codeBrowserCopySpecialAction.isEnabled());
		copySpecial(codeViewerWrapper, codeBrowserCopySpecialAction);

		assertTrue(codeBrowserPasteAction.isEnabled());

		// clear the selection and clipboard
		codeViewerWrapper.clearSelection();
		clearClipboardContents();

		// check copy on selection state
		makeSelection(decompilerWrapper);
		copy(decompilerWrapper, decompileCopyAction);

		// clear the selection and clipboard
		decompilerWrapper.clearSelection();
		clearClipboardContents();
	}

	@Test
	public void testCopyPasteAcrossServiceProviders() {
		DockingAction byteViewerCopyAction =
			getAction(byteViewerClipboardProvider, COPY_ACTION_NAME);
		DockingAction codeBrowserCopyAction =
			getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		DockingAction decompileCopyAction = getAction(decompileClipboardProvider, COPY_ACTION_NAME);

		DockingAction byteViewerPasteAction =
			getAction(byteViewerClipboardProvider, PASTE_ACTION_NAME);
		DockingAction codeBrowserPasteAction =
			getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);

		// byte viewer to code browser and decompiler
		makeSelection(byteViewerWrapper);
		copy(byteViewerWrapper, byteViewerCopyAction);

		assertFalse(byteViewerPasteAction.isEnabled());
		setByteViewerEditable(true);
		assertTrue(byteViewerPasteAction.isEnabled());
		assertTrue(codeBrowserPasteAction.isEnabled());

		codeViewerWrapper.clearSelection();
		clearClipboardContents();

		// sanity check
		assertFalse(byteViewerPasteAction.isEnabled());
		assertFalse(codeBrowserPasteAction.isEnabled());

		// code browser to byte viewer and decompiler
		makeSelection(codeViewerWrapper);
		copy(codeViewerWrapper, codeBrowserCopyAction);

// TODO: if we ever find a way to prevent the paste action from being enabled without
// actually doing the paste, then the following code can be put back in the test
//assertTrue( !byteViewerPasteAction.isEnabled() );
//assertTrue( !codeBrowserPasteAction.isEnabled() );

		// now perform a 'copy special' and choose a type that the paste will accept
		DockingAction codeBrowserCopySpecialAction =
			getAction(codeBrowserClipboardProvider, COPY_SPECIAL_ACTION_NAME);
		copySpecial(codeViewerWrapper, codeBrowserCopySpecialAction);

		assertTrue(byteViewerPasteAction.isEnabled());
		assertTrue(codeBrowserPasteAction.isEnabled());

		// change the edit state of the byte viewer and make sure we can paste
		setByteViewerEditable(true);

		assertTrue(byteViewerPasteAction.isEnabled());

		// clear the selection and clipboard
		codeViewerWrapper.clearSelection();
		clearClipboardContents();

		// sanity check
		assertFalse(byteViewerPasteAction.isEnabled());
		assertFalse(codeBrowserPasteAction.isEnabled());

		// copy from decompiler can not paste into the other two
		makeSelection(decompilerWrapper);
		copy(decompilerWrapper, decompileCopyAction);

// TODO: if we ever find a way to prevent the paste action from being enabled without
// actually doing the paste, then the following code can be put back in the test
//assertTrue( !byteViewerPasteAction.isEnabled() );
//assertTrue( !codeBrowserPasteAction.isEnabled() );
	}

	@Test
	public void testCopyPasteAcrossServiceProviders_CodeBrowser_To_ByteViewer() throws Exception {
		DockingAction codeBrowserCopyAction =
			getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		final DockingAction byteViewerPasteAction =
			getAction(byteViewerClipboardProvider, PASTE_ACTION_NAME);

		// code browser to byte viewer and decompiler
		makeSelection(codeViewerWrapper);
		copy(codeViewerWrapper, codeBrowserCopyAction);

		// now perform a 'copy special' and choose a type that the paste will accept
		DockingAction codeBrowserCopySpecialAction =
			getAction(codeBrowserClipboardProvider, COPY_SPECIAL_ACTION_NAME);
		copySpecial(codeViewerWrapper, codeBrowserCopySpecialAction);

		String clipboardContents = getClipboardContents();

		// move the cursor down to paste our bytes; clear the code we need to be able to paste
		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();
		Address pasteAddress = currentSelection.getMaxAddress();
		long pasteLength = currentSelection.getNumAddresses();
		clearSelectedBytes(pasteAddress, pasteLength);

		codeBrowserPlugin.goTo(new ProgramLocation(program, pasteAddress));

		// change the edit state of the byte viewer and make sure we can paste
		setByteViewerEditable(true);

		assertTrue(byteViewerPasteAction.isEnabled());

		runSwing(() -> byteViewerPasteAction.actionPerformed(getActionContext(byteViewerWrapper)),
			false);

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		pressButton(d.getDefaultButton());

		waitForBusyTool(tool);

		assertByteViewerBytes(clipboardContents, pasteAddress);
	}

	@Test
	public void testCopyPasteAcrossServiceProviders_CodeBrowser_To_ByteViewer_BytesWithNoSpaces()
			throws Exception {
		DockingAction codeBrowserCopyAction =
			getAction(codeBrowserClipboardProvider, COPY_ACTION_NAME);
		final DockingAction byteViewerPasteAction =
			getAction(byteViewerClipboardProvider, PASTE_ACTION_NAME);

		// code browser to byte viewer and decompiler
		makeSelection(codeViewerWrapper);
		copy(codeViewerWrapper, codeBrowserCopyAction);

		// now perform a 'copy special' and choose a type that the paste will accept
		DockingAction codeBrowserCopySpecialAction =
			getAction(codeBrowserClipboardProvider, COPY_SPECIAL_ACTION_NAME);
		copySpecial_ByteStringNoSpaces(codeViewerWrapper, codeBrowserCopySpecialAction);

		String clipboardContents = getClipboardContents();

		// move the cursor down to paste our bytes; clear the code we need to be able to paste
		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();
		Address pasteAddress = currentSelection.getMaxAddress();
		long pasteLength = currentSelection.getNumAddresses();
		clearSelectedBytes(pasteAddress, pasteLength);

		codeBrowserPlugin.goTo(new ProgramLocation(program, pasteAddress));

		// change the edit state of the byte viewer and make sure we can paste
		setByteViewerEditable(true);

		assertTrue(byteViewerPasteAction.isEnabled());

		runSwing(() -> byteViewerPasteAction.actionPerformed(getActionContext(byteViewerWrapper)),
			false);

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		pressButton(d.getDefaultButton());

		waitForBusyTool(tool);

		assertByteViewerBytes(clipboardContents, pasteAddress);
	}

	@Test
	public void testCopyTextSelection_ByteViewer_SingleLayout() throws Exception {

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setByteViewerViewSelected(dialog, "Ascii", true);
		setByteViewerViewSelected(dialog, "Octal", true);
		pressButtonByText(dialog.getComponent(), "OK");

		ByteViewerPlugin plugin = env.getPlugin(ByteViewerPlugin.class);
		ProgramByteViewerComponentProvider provider = plugin.getProvider();
		ByteViewerPanel panel =
			(ByteViewerPanel) invokeInstanceMethod("getByteViewerPanel", provider);

		Window window = windowForComponent(panel);
		assertNotNull(window);
		Dimension size = window.getSize();
		window.setSize(1000, size.height);// resize so that we can click the various views

		//
		// Test copying from the Hex view
		//
		ByteViewerComponent bc = findByteViewerComponent(panel, "Hex");
		assertTrue(bc.isVisible());

		Rectangle bounds = bc.getBounds();
		clickMouse(bc, 1, bounds.x + 20, bounds.y + 20, 1, 0);

		ProgramSelection selection =
			new ProgramSelection(program.getAddressFactory(), addr("1001050"), addr("1001052"));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));

		waitForBusyTool(tool);

		final DockingAction byteViewerCopyAction =
			getAction(byteViewerClipboardProvider, COPY_ACTION_NAME);
		runSwing(() -> byteViewerCopyAction.actionPerformed(getActionContext(byteViewerWrapper)));

		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
		Object data = contents.getTransferData(DataFlavor.stringFlavor);
		assertEquals("0e 5e f4", data);

		//
		// Test copying from the Hex view
		//
		bc = findByteViewerComponent(panel, "Ascii");
		assertTrue(bc.isVisible());

		bounds = bc.getBounds();
		clickMouse(bc, 1, bounds.x + 20, bounds.y + 20, 1, 0);

		selection =
			new ProgramSelection(program.getAddressFactory(), addr("1001050"), addr("1001052"));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));

		waitForBusyTool(tool);

		runSwing(() -> byteViewerCopyAction.actionPerformed(getActionContext(byteViewerWrapper)));

		systemClipboard = GClipboard.getSystemClipboard();
		contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
		data = contents.getTransferData(DataFlavor.stringFlavor);
		assertEquals(". ^ .", data);

		//
		// Test copying from the Octal view
		//
		bc = findByteViewerComponent(panel, "Octal");
		assertTrue(bc.isVisible());

		bounds = bc.getBounds();
		clickMouse(bc, 1, bounds.x + 20, bounds.y + 20, 1, 0);

		selection =
			new ProgramSelection(program.getAddressFactory(), addr("1001050"), addr("1001052"));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));

		waitForBusyTool(tool);

		runSwing(() -> byteViewerCopyAction.actionPerformed(getActionContext(byteViewerWrapper)));

		systemClipboard = GClipboard.getSystemClipboard();
		contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
		data = contents.getTransferData(DataFlavor.stringFlavor);
		assertEquals("016 136 364", data);
	}

	@Test
	public void testCopyTextSelection_ByteViewer_MultipleLayout() throws Exception {
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setByteViewerViewSelected(dialog, "Ascii", true);
		setByteViewerViewSelected(dialog, "Octal", true);
		pressButtonByText(dialog.getComponent(), "OK");

		ByteViewerPlugin plugin = env.getPlugin(ByteViewerPlugin.class);
		ProgramByteViewerComponentProvider provider = plugin.getProvider();
		ByteViewerPanel panel =
			(ByteViewerPanel) invokeInstanceMethod("getByteViewerPanel", provider);

		Window window = windowForComponent(panel);
		assertNotNull(window);
		Dimension size = window.getSize();
		window.setSize(1000, size.height);// resize so that we can click the various views

		//
		// Test copying from the Hex view
		//
		ByteViewerComponent bc = findByteViewerComponent(panel, "Hex");
		assertTrue(bc.isVisible());

		Rectangle bounds = bc.getBounds();
		clickMouse(bc, 1, bounds.x + 20, bounds.y + 20, 1, 0);

		ProgramSelection selection =
			new ProgramSelection(program.getAddressFactory(), addr("1001051"), addr("1001070"));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));

		waitForBusyTool(tool);

		final DockingAction byteViewerCopyAction =
			getAction(byteViewerClipboardProvider, COPY_ACTION_NAME);
		runSwing(() -> byteViewerCopyAction.actionPerformed(getActionContext(byteViewerWrapper)));

		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
		Object data = contents.getTransferData(DataFlavor.stringFlavor);
		assertEquals("5e f4 77 33 58 f4 77 91 45 f4 77 88 7c f4 77 8d 70 f5 77 05 " +
			"62 f4 77 f0 a3 f4 77 09 56 f4 77 10", data);

		//
		// Test copying from the Hex view
		//
		bc = findByteViewerComponent(panel, "Ascii");
		assertTrue(bc.isVisible());

		bounds = bc.getBounds();
		clickMouse(bc, 1, bounds.x + 20, bounds.y + 20, 1, 0);

		selection =
			new ProgramSelection(program.getAddressFactory(), addr("1001051"), addr("1001070"));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));

		waitForBusyTool(tool);

		runSwing(() -> byteViewerCopyAction.actionPerformed(getActionContext(byteViewerWrapper)));

		systemClipboard = GClipboard.getSystemClipboard();
		contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
		data = contents.getTransferData(DataFlavor.stringFlavor);
		assertEquals("^ . w 3 X . w . E . w . | . w . p . w . b . w . . . w . V . w .", data);

		//
		// Test copying from the Octal view
		//
		bc = findByteViewerComponent(panel, "Octal");
		assertTrue(bc.isVisible());

		bounds = bc.getBounds();
		clickMouse(bc, 1, bounds.x + 20, bounds.y + 20, 1, 0);

		selection =
			new ProgramSelection(program.getAddressFactory(), addr("1001051"), addr("1001070"));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));

		waitForBusyTool(tool);

		runSwing(() -> byteViewerCopyAction.actionPerformed(getActionContext(byteViewerWrapper)));

		systemClipboard = GClipboard.getSystemClipboard();
		contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
		data = contents.getTransferData(DataFlavor.stringFlavor);
		assertEquals("136 364 167 063 130 364 167 221 105 364 167 210 174 364 167 215 160 " +
			"365 167 005 142 364 167 360 243 364 167 011 126 364 167 020", data);
	}

	@Test
	public void testCodeBrowserPasteAsciiBytes() throws Exception {
		//
		// Test that we can paste characters from clipboard that contain some other special characters
		// that are not normal ascii text and only the normal ascii text will get pasted.
		// So, we have to perform the following steps to test the code:
		// 1) Put ill formed characters into clipboard
		// 2) Put the cursor on the code unit for pasting.
		// 3) Paste the bytes
		// 4) Verify the bytes don't contain the non-ascii text.
		//

		final char[] droppedChars =
			new char[] { (char) 0x30, (char) 0x31, (char) 0xa0, (char) 0xc2, (char) 0x01,
				(char) 0x63, (char) 0x30, (char) 0xa0, (char) 0x35, (char) 0x65, (char) 0x20 };
//		final byte[] pastedBytes =
//			new byte[] { (byte) 0x30, (byte) 0x31, (byte) 0x63, (byte) 0x30, (byte) 0x35,
//				(byte) 0x65 };
		final byte[] resultBytes = new byte[] { (byte) 0x01, (byte) 0xc0, (byte) 0x5e };

		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable transferable = new Transferable() {

			@Override
			public boolean isDataFlavorSupported(DataFlavor flavor) {
				if (flavor.equals(DataFlavor.stringFlavor)) {
					return true;
				}
				return false;
			}

			@Override
			public DataFlavor[] getTransferDataFlavors() {
				return new DataFlavor[] { DataFlavor.stringFlavor };
			}

			@Override
			public Object getTransferData(DataFlavor flavor)
					throws UnsupportedFlavorException, IOException {
				if (flavor.equals(DataFlavor.stringFlavor)) {
					return new String(droppedChars);
				}
				return null;
			}
		};
		// 1) Put ill formed characters into clipboard
		systemClipboard.setContents(transferable, (clipboard, contents) -> {
			// dummy listener so that we can be properly garbage collected
		});
		Transferable contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
		Object data = contents.getTransferData(DataFlavor.stringFlavor);
		assertEquals(new String(droppedChars), data);

		AddressFieldLocation location = new AddressFieldLocation(program, addr("01002cf0"));
		// 2) Put the cursor on the code unit for pasting.
		codeBrowserPlugin.goTo(location);

		ActionContext context = codeViewerProvider.getActionContext(null);

		DockingAction pasteAction = getAction(codeBrowserClipboardProvider, PASTE_ACTION_NAME);
		context = codeViewerProvider.getActionContext(null);
		// 3) Paste the bytes
		performAction(pasteAction, context, false);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		pressButton(d.getDefaultButton());

		waitForBusyTool(tool);

		ProgramLocation currentLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue(currentLocation instanceof AddressFieldLocation);
		AddressFieldLocation addressLocation = (AddressFieldLocation) currentLocation;
		assertEquals("01002cf0", addressLocation.getAddressRepresentation());
		Address address = addressLocation.getAddress();
		Memory memory = program.getMemory();
		byte[] memoryBytes = new byte[resultBytes.length];
		// 4) Verify the bytes don't contain the non-ascii text.
		memory.getBytes(address, memoryBytes, 0, resultBytes.length);
		assertTrue("The expected bytes were not pasted in the CodeBrowser.",
			Arrays.equals(resultBytes, memoryBytes));
	}

	@Test
	public void testByteViewerPasteAsciiBytes() throws Exception {
		final DockingAction byteViewerPasteAction =
			getAction(byteViewerClipboardProvider, PASTE_ACTION_NAME);
		//
		// Test that we can paste characters from clipboard that contain some other special characters
		// that are not normal ascii text and only the normal ascii text will get pasted.
		// So, we have to perform the following steps to test the code:
		// 1) Put ill formed characters into clipboard
		// 2) Put the cursor on the byte viewer address for pasting.
		// 3) Paste the bytes
		// 4) Verify the bytes don't contain the non-ascii text.
		//

		final char[] droppedChars =
			new char[] { (char) 0x30, (char) 0x31, (char) 0xa0, (char) 0xc2, (char) 0x01,
				(char) 0x63, (char) 0x30, (char) 0xa0, (char) 0x35, (char) 0x65, (char) 0x20 };
//		final byte[] pastedBytes =
//			new byte[] { (byte) 0x30, (byte) 0x31, (byte) 0x63, (byte) 0x30, (byte) 0x35,
//				(byte) 0x65 };
		final byte[] resultBytes = new byte[] { (byte) 0x01, (byte) 0xc0, (byte) 0x5e };

		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable transferable = new Transferable() {

			@Override
			public boolean isDataFlavorSupported(DataFlavor flavor) {
				if (flavor.equals(DataFlavor.stringFlavor)) {
					return true;
				}
				return false;
			}

			@Override
			public DataFlavor[] getTransferDataFlavors() {
				return new DataFlavor[] { DataFlavor.stringFlavor };
			}

			@Override
			public Object getTransferData(DataFlavor flavor)
					throws UnsupportedFlavorException, IOException {
				if (flavor.equals(DataFlavor.stringFlavor)) {
					return new String(droppedChars);
				}
				return null;
			}
		};
		// 1) Put ill formed characters into clipboard
		systemClipboard.setContents(transferable, (clipboard, contents) -> {
			// dummy listener so that we can be properly garbage collected
		});
		Transferable contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
		Object data = contents.getTransferData(DataFlavor.stringFlavor);
		assertEquals(new String(droppedChars), data);

		Address address = program.getAddressFactory().getAddress("01002cf0");
		AddressFieldLocation location = new AddressFieldLocation(program, address);
		// 2) Put the cursor on the byte viewer address for pasting.
		codeBrowserPlugin.goTo(location);

		// change the edit state of the byte viewer and make sure we can paste
		setByteViewerEditable(true);

		assertTrue(byteViewerPasteAction.isEnabled());

		// 3) Paste the bytes
		runSwing(() -> byteViewerPasteAction.actionPerformed(getActionContext(byteViewerWrapper)),
			false);

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		pressButton(d.getDefaultButton());

		waitForSwing();

		Memory memory = program.getMemory();
		byte[] memoryBytes = new byte[resultBytes.length];
		// 4) Verify the bytes don't contain the non-ascii text.
		memory.getBytes(address, memoryBytes, 0, resultBytes.length);
		assertTrue("The expected bytes were not pasted in the ByteViewer.",
			Arrays.equals(resultBytes, memoryBytes));
	}

//==================================================================================================
// Helper Methods
//==================================================================================================

	private ByteViewerOptionsDialog launchByteViewerOptions() {
		Plugin plugin = env.getPlugin(ByteViewerPlugin.class);
		final DockingActionIf action = getAction(plugin, "Byte Viewer Options");
		assertTrue(action.isEnabled());

		SwingUtilities.invokeLater(() -> action.actionPerformed(new ActionContext()));
		waitForSwing();
		ByteViewerOptionsDialog d = waitForDialogComponent(ByteViewerOptionsDialog.class);
		return d;
	}

	private void setByteViewerViewSelected(ByteViewerOptionsDialog dialog, String viewName,
			boolean selected) {
		Map<?, ?> checkboxMap = (Map<?, ?>) getInstanceField("checkboxMap", dialog);
		JCheckBox checkbox = (JCheckBox) checkboxMap.get(viewName);
		checkbox.setSelected(selected);
	}

	private ByteViewerComponent findByteViewerComponent(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof ByteViewerComponent) {
				DataFormatModel model =
					(DataFormatModel) invokeInstanceMethod("getDataModel", element);
				if (model.getName().equals(name)) {
					return (ByteViewerComponent) element;
				}
			}
			else if (element instanceof Container) {
				ByteViewerComponent bvc = findByteViewerComponent((Container) element, name);
				if (bvc != null) {
					return bvc;
				}
			}
		}
		return null;
	}

	private void setByteViewerEditable(boolean editable) {
		ComponentProvider provider =
			(ComponentProvider) getInstanceField("connectedProvider", byteViewerPlugin);

		ToggleDockingActionIf action =
			(ToggleDockingActionIf) getInstanceField("editModeAction", provider);

		if (editable == action.isSelected()) {
			return;
		}

		performAction(action, true);
	}

	private void makeSelection(ComponentProviderWrapper wrapper) {
		ComponentProvider provider = wrapper.getComponentProvider();

		wrapper.clearSelection();

		Component component = provider.getComponent();

		Point point = wrapper.getStartMouseDragLocation();
		int startX = point.x;
		int startY = point.y;

		Point endPoint = wrapper.getEndMouseDragLocation();
		int endX = endPoint.x;
		int endY = endPoint.y;

		final Component deepestComponent =
			SwingUtilities.getDeepestComponentAt(component, startX, startY);
		Msg.debug(this, "Preparing to make a selection on Java component \"" + deepestComponent +
			"\" for test " + wrapper.getComponentProvider().getName());
//        Container parent = deepestComponent.getParent();
//        while ( parent != null ) {
//            Err.debug( this, "\twith parent: " + parent );
//            parent = parent.getParent();
//        }
		dragMouse(deepestComponent, MouseEvent.BUTTON1, startX, startY, endX, endY, 0);
		Msg.debug(this, "\tafter make selection");

		wrapper.verifySelection();
	}

	private void clearClipboardContents() {
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		systemClipboard.setContents(DUMMY_TRANSFERABLE, null);
		waitForSwing();

		// something useful or snarky, it's up to me.
		// make sure that the state is initialized properly, because the
		// testing environment might have cruft in it (note, normal environment
		// has cruft too) and this updates the stuff in the stuff
		TestUtils.invokeInstanceMethod("updateCopyState", clipboardPlugin);
		TestUtils.invokeInstanceMethod("updatePasteState", clipboardPlugin);
	}

	private String getClipboardContents() throws Exception {
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable transferable = systemClipboard.getContents(this);
		return (String) transferable.getTransferData(DataFlavor.stringFlavor);
	}

	private void copy(ComponentProviderWrapper wrapper, final DockingAction copyAction) {
		wrapper.verifySelection();

		runSwing(() -> {
			copyAction.actionPerformed(getActionContext(wrapper));
		});

		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
	}

	private ActionContext getActionContext(ComponentProviderWrapper wrapper) {
		return runSwing(() -> {
			ComponentProvider provider = wrapper.getComponentProvider();
			ActionContext context = provider.getActionContext(null);
			return context;
		});
	}

	private void copySpecial(ComponentProviderWrapper wrapper, final DockingAction copyAction) {

		executeOnSwingWithoutBlocking(() -> copyAction.actionPerformed(getActionContext(wrapper)));

		// get the dialog and make a selection
		JDialog dialog = waitForJDialog("Copy Special");
		assertNotNull(dialog);
		DockingDialog dockingDialog = (DockingDialog) dialog;
		final DialogComponentProvider component =
			(DialogComponentProvider) getInstanceField("component", dockingDialog);
		Object listPanel = getInstanceField("listPanel", component);
		final JList<?> list = (JList<?>) getInstanceField("list", listPanel);

		runSwing(() -> {
			list.setSelectedValue(ByteCopier.BYTE_STRING_TYPE, true);
			JButton okButton = (JButton) getInstanceField("okButton", component);
			okButton.doClick();
		});

		waitForTasks();
	}

	private void copySpecial_ByteStringNoSpaces(ComponentProviderWrapper wrapper,
			final DockingAction copyAction) {
		wrapper.verifySelection();
		executeOnSwingWithoutBlocking(() -> copyAction.actionPerformed(getActionContext(wrapper)));

		// get the dialog and make a selection
		JDialog dialog = waitForJDialog("Copy Special");
		assertNotNull(dialog);
		DockingDialog dockingDialog = (DockingDialog) dialog;
		final DialogComponentProvider component =
			(DialogComponentProvider) getInstanceField("component", dockingDialog);
		Object listPanel = getInstanceField("listPanel", component);
		final JList<?> list = (JList<?>) getInstanceField("list", listPanel);

		runSwing(() -> {
			list.setSelectedValue(ByteCopier.BYTE_STRING_NO_SPACE_TYPE, true);
			JButton okButton = (JButton) getInstanceField("okButton", component);
			okButton.doClick();
		});

		waitForTasks();
	}

	private void assertByteViewerBytes(String clipboardContents, Address address)
			throws MemoryAccessException, AddressOutOfBoundsException {
		Memory memory = program.getMemory();

		//b090db777880db774893db77
		// expecting a bytes string of the format: b0 90 db 77 78 80 db 77 48 93 db 77
		String[] bytes = null;
		if (clipboardContents.contains(" ")) {
			bytes = clipboardContents.split("\\s");
		}
		else {
			bytes = new String[clipboardContents.length() >> 1];
			for (int i = 0; i < bytes.length; i++) {
				int stringOffset = i * 2;
				bytes[i] = clipboardContents.substring(stringOffset, stringOffset + 2);
			}
		}
		for (int i = 0; i < bytes.length; i++) {
			byte bite = memory.getByte(address.add(i));
			if (!bytes[i].equals(Integer.toHexString(bite & 0xFF))) {
				Msg.debug(this, "not equal at index: " + i);
			}
			assertEquals("Bytes not pasted as expected", bytes[i],
				Integer.toHexString(bite & 0xFF));
		}
	}

	private void clearSelectedBytes(Address address, long length) {
		AddressSet addressSet = new AddressSet(address);
		for (int i = 1; i < length; i++) {
			addressSet.add(address.add(i));
		}

		int startTransaction = program.startTransaction("Test - Clear Bytes");
		try {
			ClearCmd clearCmd = new ClearCmd(addressSet);
			clearCmd.applyTo(program);
		}
		finally {
			program.endTransaction(startTransaction, true);
		}
	}

	/*
	 * We remove the FieldPanel focus listeners for these tests, as when they lose focus, 
	 * the selection mechanism does not work as expected.  Focus changes can happen 
	 * indeterminately during parallel batch testing.
	 */
	private void removeFieldPanelFocusListeners(Container c) {
		if (c instanceof FieldPanel) {
			removeFocusListeners((JComponent) c);
		}

		Component[] children = c.getComponents();
		for (Component child : children) {
			if (!(child instanceof Container)) {
				continue;
			}
			removeFieldPanelFocusListeners((Container) child);
		}
	}

	private void removeFocusListeners(JComponent c) {
		FocusListener[] listeners = c.getFocusListeners();
		for (FocusListener l : listeners) {
			c.removeFocusListener(l);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	interface ComponentProviderWrapper {
		public Point getStartMouseDragLocation();

		public ActionContext getContext();

		public Point getEndMouseDragLocation();

		public void clearSelection();

		public void verifySelection();

		public ComponentProvider getComponentProvider();
	}

	class ByteViewerWrapper implements ComponentProviderWrapper {
		private final ByteViewerComponentProvider provider;

		public ByteViewerWrapper(ComponentProvider provider) {
			this.provider = (ByteViewerComponentProvider) provider;

			removeFieldPanelFocusListeners(provider.getComponent());
		}

		@Override
		public void verifySelection() {
			Object byteViewerPanel = getInstanceField("panel", provider);
			ByteBlockSelection byteBlockSelection =
				(ByteBlockSelection) invokeInstanceMethod("getViewerSelection", byteViewerPanel);
			assertTrue("No selection in the byte viewer.",
				byteBlockSelection.getNumberOfRanges() > 0);
		}

		@Override
		public Point getStartMouseDragLocation() {
			return new Point(100, 30);
		}

		@Override
		public Point getEndMouseDragLocation() {
			return new Point(300, 30);
		}

		@Override
		public ComponentProvider getComponentProvider() {
			return provider;
		}

		@Override
		public ActionContext getContext() {
			return provider.getActionContext(null);
		}

		@Override
		public void clearSelection() {
			Object byteViewerPanel = getInstanceField("panel", provider);
			runSwing(() -> {
				invokeInstanceMethod("setViewerSelection", byteViewerPanel,
					new Class[] { ByteBlockSelection.class },
					new Object[] { new ByteBlockSelection() });
			});

		}
	}

	class CodeViewerWrapper implements ComponentProviderWrapper {

		private final CodeViewerProvider provider;

		public CodeViewerWrapper(CodeViewerProvider provider) {
			this.provider = provider;

			removeFieldPanelFocusListeners(provider.getComponent());
		}

		@Override
		public void verifySelection() {
			ProgramSelection selection = provider.getSelection();
			if (!selection.isEmpty()) {
				return;
			}

			CodeBrowserClipboardProvider clipboardProvider =
				(CodeBrowserClipboardProvider) getInstanceField("codeViewerClipboardProvider",
					provider);

			assertTrue("No selection in the code browser.",
				clipboardProvider.getStringContent() != null);
		}

		@Override
		public Point getStartMouseDragLocation() {
			return new Point(100, 110);
		}

		@Override
		public Point getEndMouseDragLocation() {
			return new Point(300, 210);
		}

		@Override
		public ComponentProvider getComponentProvider() {
			return provider;
		}

		@Override
		public ActionContext getContext() {
			return provider.getActionContext(null);
		}

		@Override
		public void clearSelection() {
			runSwing(() -> provider.programSelectionChanged(new ProgramSelection()));
		}
	}

	class DecompilerWrapper implements ComponentProviderWrapper {

		private final DecompilerProvider provider;

		public DecompilerWrapper(ComponentProvider provider) {
			this.provider = (DecompilerProvider) provider;

			removeFieldPanelFocusListeners(provider.getComponent());
		}

		@Override
		public void verifySelection() {
			Object controller = getInstanceField("controller", provider);
			Object decompilerPanel = getInstanceField("decompilerPanel", controller);
			FieldPanel fieldPanel = (FieldPanel) getInstanceField("fieldPanel", decompilerPanel);
			FieldSelection selection = fieldPanel.getSelection();
			assertTrue("No selection in the decompile provider.", !selection.isEmpty());
		}

		@Override
		public Point getStartMouseDragLocation() {
			return new Point(10, 5);
		}

		@Override
		public Point getEndMouseDragLocation() {
			return new Point(210, 5);
		}

		@Override
		public ComponentProvider getComponentProvider() {
			return provider;
		}

		@Override
		public ActionContext getContext() {
			return provider.getActionContext(null);
		}

		@Override
		public void clearSelection() {
			runSwing(() -> provider.setSelection(new ProgramSelection()));
		}
	}

	static class DummyTransferable implements Transferable {

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			return null;
		}

		@Override
		public DataFlavor[] getTransferDataFlavors() {
			return new DataFlavor[0];
		}

		@Override
		public boolean isDataFlavorSupported(DataFlavor flavor) {
			return true;
		}

	}
}
