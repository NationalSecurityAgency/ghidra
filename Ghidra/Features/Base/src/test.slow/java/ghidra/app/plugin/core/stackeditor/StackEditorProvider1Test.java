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

import java.awt.Window;

import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.Test;

import docking.action.DockingActionIf;
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

public class StackEditorProvider1Test extends AbstractStackEditorProviderTest {

	public StackEditorProvider1Test() {
		super();
	}

	// Change LOCAL size.
	@Test
	public void testIncreaseNegLocalSize() throws Exception {
		init(SIMPLE_STACK);
		assertEquals(0x1e, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		JTextField localSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Local Size", true);
		setField(localSizeField, "0x18");
		assertEquals(0x22, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x18, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
	}

	@Test
	public void testDecreaseNegLocalSize() throws Exception {
		init(SIMPLE_STACK);
		assertEquals(0x1e, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		JTextField localSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Local Size", true);
		setField(localSizeField, "0x11");
		assertEquals(0x1b, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x11, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		assertTrue(getDataType(0).isEquivalent(DataType.DEFAULT));
		assertEquals(20, stackModel.getNumComponents());
	}

	// Change PARAM size.
	@Test
	public void testIncreaseNegParamSize() throws Exception {
		init(SIMPLE_STACK);
		assertEquals(0x1e, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		JTextField paramSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Parameter Size", true);
		setField(paramSizeField, "0xc");
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xc, stackModel.getParameterSize());
	}

	@Test
	public void testDecreaseNegParamSize() throws Exception {
		init(SIMPLE_STACK);
		assertEquals(0x1e, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		JTextField paramSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Parameter Size", true);
		setField(paramSizeField, "0x8");
		assertEquals(0x1c, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0x8, stackModel.getParameterSize());
	}

	@Test
	public void testEditChangedStackAndDeleteFunction() throws Exception {
		DockingActionIf deleteFunction = getAction(functionPlugin, "Delete Function");

		editStack(function.getEntryPoint().toString());

		// Put a byte at -0x1b
		setType(new ByteDataType(), 2);

		performAction(deleteFunction, cb.getProvider(), true);
		waitForBusyTool(tool);
		waitForSwing();

		assertStackEditorHidden(function);
	}

	@Test
	public void testEditUnchangedStackAndDeleteFunction() throws Exception {
		DockingActionIf deleteFunction = getAction(functionPlugin, "Delete Function");

		editStack(function.getEntryPoint().toString());
		performAction(deleteFunction, cb.getProvider(), true);
		waitForBusyTool(tool);

		assertStackEditorHidden(function);
	}

	@Test
	public void testUndoAssociatedFunctionCreate() throws Exception {
		Window dialog;
		// Create the stack frame @ 00000200.
		createFunction("0x200");
		editStack("0x200");

		Function f = program.getFunctionManager().getFunctionAt(addr("0x200"));
		assertStackEditorShowing(f);

		installProvider(stackEditorMgr.getProvider(program, "FUN_00000200"));
		assertNotNull(provider);
		model = ((StackEditorProvider) provider).getModel();
		assertNotNull(model);

		JTextField localSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Local Size", true);
		setField(localSizeField, "0x18");
		// Put byte at -0x18
		setType(new ByteDataType(), 0);

		// Undo the apply of a new data type to an editor component.
		undo(program, false); // don't wait, in case there is a modal dialog
		waitForSwing();

		// Verify the Reload Stack Editor? dialog is not displayed.
		dialog = getWindow("Reload Stack Editor?");
		assertNull(dialog);

		// Verify the stack editor is not displayed.
		assertStackEditorHidden(f);
	}

	@Test
	public void testChangeHexNumbersOption() throws Exception {
		editStack(function.getEntryPoint().toString());

		StackEditorPanel panel = (StackEditorPanel) provider.getComponent();
		Options options = tool.getOptions("Editors");
		String hexNumbersName = "Stack Editor" + Options.DELIMITER + "Show Numbers In Hex";

		// Get the hex option values
		boolean hexNumbers = options.getBoolean(hexNumbersName, false);
		assertEquals(true, hexNumbers);
		// Check the values are in hexadecimal
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("-0x10", model.getValueAt(0, model.getOffsetColumn()));
		assertEquals("0x4", model.getValueAt(3, model.getLengthColumn()));

		assertEquals("0x20", ((JTextField) findComponentByName(panel, "Frame Size")).getText());
		assertEquals("0x14", ((JTextField) findComponentByName(panel, "Local Size")).getText());
		assertEquals("0xc", ((JTextField) findComponentByName(panel, "Parameter Size")).getText());
		assertEquals("0x4",
			((JTextField) findComponentByName(panel, "Parameter Offset")).getText());
		assertEquals("0x0",
			((JTextField) findComponentByName(panel, "Return Address Offset")).getText());

		// Set the hex offset option value to decimal
		options.setBoolean(hexNumbersName, false);
		panel = (StackEditorPanel) provider.getComponent();

		// Get the hex option values
		hexNumbers = options.getBoolean(hexNumbersName, false);
		assertEquals(false, hexNumbers);
		// Check the values (offset should still be hexadecimal in editor)
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("-0x10", model.getValueAt(0, model.getOffsetColumn()));
		assertEquals("0x4", model.getValueAt(3, model.getLengthColumn()));
		assertEquals("0x20", ((JTextField) findComponentByName(panel, "Frame Size")).getText());
		assertEquals("0x14", ((JTextField) findComponentByName(panel, "Local Size")).getText());
		assertEquals("0xc", ((JTextField) findComponentByName(panel, "Parameter Size")).getText());
		assertEquals("0x4",
			((JTextField) findComponentByName(panel, "Parameter Offset")).getText());
		assertEquals("0x0",
			((JTextField) findComponentByName(panel, "Return Address Offset")).getText());

		// Close the editor
		SwingUtilities.invokeLater(() -> provider.closeComponent());
		waitForSwing();
		// Editor should be closed.
		assertTrue(!tool.isVisible(provider));
		// Re-open the editor
		editStack(function.getEntryPoint().toString());
		panel = (StackEditorPanel) provider.getComponent();

		// Get the hex option values (offset should now be decimal in editor)
		hexNumbers = options.getBoolean(hexNumbersName, false);
		assertEquals(false, hexNumbers);
		// Check the offset value is in decimal
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("-16", model.getValueAt(0, model.getOffsetColumn()));
		assertEquals("4", model.getValueAt(3, model.getLengthColumn()));
		assertEquals("32", ((JTextField) findComponentByName(panel, "Frame Size")).getText());
		assertEquals("20", ((JTextField) findComponentByName(panel, "Local Size")).getText());
		assertEquals("12", ((JTextField) findComponentByName(panel, "Parameter Size")).getText());
		assertEquals("4", ((JTextField) findComponentByName(panel, "Parameter Offset")).getText());
		assertEquals("0",
			((JTextField) findComponentByName(panel, "Return Address Offset")).getText());

		// Set the hex offset option value to hexadecimal
		options.setBoolean(hexNumbersName, true);
		panel = (StackEditorPanel) provider.getComponent();

		// Get the hex option values
		hexNumbers = options.getBoolean(hexNumbersName, false);
		assertEquals(true, hexNumbers);
		// Check the values (offset should still be decimal in editor)
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("-16", model.getValueAt(0, model.getOffsetColumn()));
		assertEquals("4", model.getValueAt(3, model.getLengthColumn()));
		assertEquals("32", ((JTextField) findComponentByName(panel, "Frame Size")).getText());
		assertEquals("20", ((JTextField) findComponentByName(panel, "Local Size")).getText());
		assertEquals("12", ((JTextField) findComponentByName(panel, "Parameter Size")).getText());
		assertEquals("4", ((JTextField) findComponentByName(panel, "Parameter Offset")).getText());
		assertEquals("0",
			((JTextField) findComponentByName(panel, "Return Address Offset")).getText());

		// Close the editor
		SwingUtilities.invokeLater(() -> provider.closeComponent());
		waitForSwing();
		// Editor should be closed.
		assertTrue(!tool.isVisible(provider));
		// Re-open the editor
		editStack(function.getEntryPoint().toString());
		panel = (StackEditorPanel) provider.getComponent();

		// Get the hex option values (offset should now be hexadecimal in editor)
		hexNumbers = options.getBoolean(hexNumbersName, false);
		assertEquals(true, hexNumbers);
		// Check the values are in hexadecimal
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("-0x10", model.getValueAt(0, model.getOffsetColumn()));
		assertEquals("0x4", model.getValueAt(3, model.getLengthColumn()));
		assertEquals("0x20", ((JTextField) findComponentByName(panel, "Frame Size")).getText());
		assertEquals("0x14", ((JTextField) findComponentByName(panel, "Local Size")).getText());
		assertEquals("0xc", ((JTextField) findComponentByName(panel, "Parameter Size")).getText());
		assertEquals("0x4",
			((JTextField) findComponentByName(panel, "Parameter Offset")).getText());
		assertEquals("0x0",
			((JTextField) findComponentByName(panel, "Return Address Offset")).getText());
	}

	@Test
	public void testExternalChangeUpdatesProvider() throws Exception {
		// Open the provider at a function
		init(SIMPLE_STACK);

		// Change the name of a parameter in the Listing
		int parameterIndex = 0;
		Parameter parameter = renameParameterInListing(parameterIndex, "listing.test.name");

		// Verify the provider's name for that parameter is updated
		String modelParameterName = getParameterNameFromModel(parameterIndex);
		assertEquals(parameter.getName(), modelParameterName);
	}

	@Test
	public void testExternalChangeWithProviderChangeDoesNotUpdateProvider() throws Exception {
		// Open the provider at a function
		init(SIMPLE_STACK);

		// Change the name of the parameter in the provider
		int parameterIndex = 0;
		String newModelName = "model.test.name";
		renameParameterInProvider(parameterIndex, newModelName);

		// Change the name of a parameter in the Listing
		renameParameterInListing(parameterIndex, "listing.test.name");

		// Verify the name of the parameter in the provider is not changed from the original edit
		String currentModelName = getParameterNameFromModel(parameterIndex);
		assertEquals(newModelName, currentModelName);
	}

	@Test
	public void testApplyProviderChangesWithExternalChanges_OverwriteExternal() throws Exception {
		// Open the provider at a function
		init(SIMPLE_STACK);

		// Change the name of the parameter in the provider
		int parameterIndex = 0;
		String newModelName = "model.test.name";
		renameParameterInProvider(parameterIndex, newModelName);

		// Change the name of a parameter in the Listing
		renameParameterInListing(parameterIndex, "listing.test.name");

		// Press Apply
		apply();

		// Get the warning dialog
		// --Choose overwrite
		chooseOverwrite();

		// Verify the Listing has the provider's changes
		String currentListingName = getParameterNameFromListing(parameterIndex);
		assertEquals(newModelName, currentListingName);
	}

	@Test
	public void testApplyProviderChangesWithExternalChanges_Cancel() throws Exception {
		// Open the provider at a function
		init(SIMPLE_STACK);

		// Change the name of the parameter in the provider
		int parameterIndex = 0;
		String newModelName = "model.test.name";
		renameParameterInProvider(parameterIndex, newModelName);

		// Change the name of a parameter in the Listing
		String newListingText = "listing.test.name";
		renameParameterInListing(parameterIndex, newListingText);

		// Press Apply
		apply();

		// Get the warning dialog
		// --Choose cancel
		chooseCancel();

		// Verify the Listing has not changed
		assertEquals(newListingText, getParameterNameFromListing(parameterIndex));

		// Verify the provider has not changed
		String currentModelName = getParameterNameFromModel(parameterIndex);
		assertEquals(newModelName, currentModelName);
	}

	@Test
	public void testUndoApplyComponentChanges() throws Exception {
		Window dialog;

		editStack(function.getEntryPoint().toString());

		// Put a byte at -0x1b
		setType(new ByteDataType(), 2);

		// Put 2 byte pointer at -0xa
		setType(new Pointer16DataType(), 2);
		assertCellString("pointer16", 2, 2);
		assertEquals(2, getLength(2));

		// Apply the changes
		invoke(applyAction);
		StackFrame stack = function.getStackFrame();
		Variable sv = stack.getVariableContaining(-0x8);
		assertEquals("pointer16", sv.getDataType().getDisplayName());
		assertEquals(2, sv.getLength());
		assertCellString("pointer16", 2, 2);
		assertEquals(2, getLength(2));

		// Undo the apply
		undo(program, true);

		// Verify the Reload Stack Editor? dialog is displayed.
		waitForSwing();
		dialog = getWindow("Reload Stack Editor?");
		assertNull(dialog);
		sv = stack.getVariableContaining(-0x8);
		assertNotNull(sv);
		assertEquals("dword", sv.getDataType().getDisplayName());
		assertEquals(4, sv.getLength());
		assertCellString("dword", 2, 2);
		assertEquals(4, getLength(2));

		// Redo the apply
		redo(program, true);

		// Verify the Reload Stack Editor? dialog is not displayed.
		waitForSwing();
		dialog = getWindow("Reload Stack Editor?");
		assertNull(dialog);
		sv = stack.getVariableContaining(-0x8);
		assertEquals("pointer16", sv.getDataType().getDisplayName());
		assertEquals(2, sv.getLength());
		assertCellString("pointer16", 2, 2);
		assertEquals(2, getLength(2));
	}

	@Test
	public void testUndoNewDtComponent() throws Exception {

		// NOTE: This test appears to verify that the undefined*16 type
		// resolved against the program DTM used by the stack editor
		// is removed on the first undo - unfortunately, the redo
		// does not restore the editor state.  It is unclear why a private 
		// DTM is not employed similar to the Structure editor which 
		// would allow the new undefined*16 type to persist after the undo (see SCR 10280)

		Window dialog;

		editStack(function.getEntryPoint().toString());

		// Put 2 byte pointer at -0x1b
		setType(new Pointer16DataType(), 4);

		// Undo the apply of a new data type to an editor component.
		undo(program, false);

		// Verify the Reload Stack Editor? dialog is displayed.
		dialog = waitForWindow("Reload Stack Editor?");
		assertNotNull(dialog);
		pressButton(dialog, "No");
		dialog.dispose();
		waitForSwing();

		dialog = getWindow("Reload Stack Editor?");
		assertNull(dialog);

		// Redo the apply
		redo(program, false);
		waitForSwing();
		dialog = getWindow("Reload Stack Editor?");
		assertNull(dialog);

		cleanup();
	}
}
