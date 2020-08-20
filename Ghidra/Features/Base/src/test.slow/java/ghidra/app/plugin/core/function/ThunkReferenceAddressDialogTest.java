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

import javax.swing.JTextField;

import org.junit.*;

import docking.AbstractErrDialog;
import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.util.viewer.field.FunctionSignatureFieldFactory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.*;

public class ThunkReferenceAddressDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin codeBrowserPlugin;
	private FunctionPlugin functionPlugin;

	private DockingActionIf editThunk;
	private DockingActionIf revertThunk;

	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		builder.createExternalFunction(null, "LibFoo", "xyz", "_Zxyz");
		program = builder.getProgram();
		tool = env.launchDefaultTool(program);

		codeBrowserPlugin = env.getPlugin(CodeBrowserPlugin.class);

		functionPlugin = getPlugin(tool, FunctionPlugin.class);
		editThunk = getAction(functionPlugin, "Set Thunked Function");
		revertThunk = getAction(functionPlugin, "Revert Thunk Function");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testSetThunkedFunction() throws Exception {

		ThunkReferenceAddressDialog dialog = showThunkDialog(addr(0x100194b));

		JTextField textEntryField = findComponent(dialog, JTextField.class);
		assertNotNull(textEntryField);

		// Invalid Entry
		setText(textEntryField, "bar");

		pressButtonByText(dialog, "OK", false);

		AbstractErrDialog errorDialog = waitForErrorDialog();
		assertEquals("Invalid Entry Error", errorDialog.getTitle());
		assertEquals(
			"Invalid thunk reference address or name specified: bar",
			errorDialog.getMessage());
		pressButtonByText(errorDialog, "OK");

		// Try again
		setText(textEntryField, "IsTextUnicode");
		pressButtonByText(dialog, "OK");
		waitForBusyTool(tool);

		Function f = program.getFunctionManager().getFunctionAt(addr(0x100194b));
		assertTrue(f.isThunk());

		Function thunkedFunction = f.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("ADVAPI32.dll::IsTextUnicode", thunkedFunction.getName(true));

	}

	@Test
	public void testSetThunkedFunctionWithNamespace() throws Exception {

		ThunkReferenceAddressDialog dialog = showThunkDialog(addr(0x100194b));

		JTextField textEntryField = findComponent(dialog, JTextField.class);
		assertNotNull(textEntryField);

		setText(textEntryField, "ADVAPI32.dll::IsTextUnicode");

		pressButtonByText(dialog, "OK");
		waitForBusyTool(tool);

		Function f = program.getFunctionManager().getFunctionAt(addr(0x100194b));
		assertTrue(f.isThunk());

		Function thunkedFunction = f.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("ADVAPI32.dll::IsTextUnicode", thunkedFunction.getName(true));

	}

	@Test
	public void testSetThunkedFunctionWithOriginalName() throws Exception {

		ThunkReferenceAddressDialog dialog = showThunkDialog(addr(0x100194b));

		JTextField textEntryField = findComponent(dialog, JTextField.class);
		assertNotNull(textEntryField);

		setText(textEntryField, "_Zxyz");

		pressButtonByText(dialog, "OK");

		waitForBusyTool(tool);

		Function f = program.getFunctionManager().getFunctionAt(addr(0x100194b));
		assertTrue(f.isThunk());

		Function thunkedFunction = f.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("LibFoo::xyz", thunkedFunction.getName(true));

	}

	@Test
	public void testSetThunkedFunctionWithOriginalNameConflict() throws Exception {

		tx(program, () -> {
			program.getSymbolTable().createLabel(addr(0x1001900), "_Zxyz", SourceType.USER_DEFINED);
		});

		ThunkReferenceAddressDialog dialog = showThunkDialog(addr(0x100194b));
		JTextField textEntryField = findComponent(dialog, JTextField.class);
		assertNotNull(textEntryField);
		setText(textEntryField, "_Zxyz");
		pressButtonByText(dialog, "OK", false);

		AbstractErrDialog errorDialog = waitForErrorDialog();
		assertEquals("Ambiguous Symbol Name", errorDialog.getTitle());
		assertEquals(
			"Specified symbol is ambiguous.  Try full namespace name, mangled name or address.",
			errorDialog.getMessage());
		pressButtonByText(errorDialog, "OK");
		waitForBusyTool(tool);

		Function f = program.getFunctionManager().getFunctionAt(addr(0x100194b));
		assertFalse(f.isThunk());

		setText(textEntryField, "LibFoo::xyz");
		pressButtonByText(dialog, "OK", false);
		waitForBusyTool(tool);

		Function thunkedFunction = f.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("LibFoo::xyz", thunkedFunction.getName(true));
	}

	private ThunkReferenceAddressDialog showThunkDialog(Address address) {
		codeBrowserPlugin.goToField(address, FunctionSignatureFieldFactory.FIELD_NAME, 0, 0);
		waitForBusyTool(tool);

		ActionContext actionContext = codeBrowserPlugin.getProvider().getActionContext(null);

		assertTrue(editThunk.isEnabledForContext(actionContext));
		assertFalse(revertThunk.isEnabledForContext(actionContext));
		performAction(editThunk, actionContext, false);

		ThunkReferenceAddressDialog dialog =
			waitForDialogComponent(ThunkReferenceAddressDialog.class);
		return dialog;
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

}
