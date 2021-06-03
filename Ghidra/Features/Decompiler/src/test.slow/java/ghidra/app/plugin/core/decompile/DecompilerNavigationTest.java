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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.gotoquery.GoToHelper;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import mockit.*;

public class DecompilerNavigationTest extends AbstractDecompilerTest {

	private boolean goToExternalLinkageCalled;

	@Before
	@Override
	public void setUp() throws Exception {
		super.setUp();

		CodeViewerProvider cbProvider = codeBrowser.getProvider();
		tool.showComponentProvider(cbProvider, true);
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	private Program buildProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("notepad", false, this);

		// need a default label at 01002cf0, so make up a reference
		builder.createMemoryReference("01002ce5", "01002cf0", RefType.FALL_THROUGH,
			SourceType.ANALYSIS);

		return builder.getProgram();
	}

	@Test
	public void testNavigation_ExternalEventDoesNotTriggerNavigation() {

		//
		// Test to make sure that external ProgramLocationEvent notifications to not trigger 
		// the Decompiler to broadcast a new event.   Setup a tool with the Listing and 
		// the Decompiler open.  Then, navigate in the Listing and verify the address does not
		// move.  (This is somewhat subject to the Code Unit at the address in how the 
		// Decompiler itself responds to the incoming event.)
		//

		// very specific location within the instruction that is known to affect how the
		// decompiler responds
		String operandPrefix = "dword ptr [EBP + ";
		String operandReferenceName = "destStr]";
		OperandFieldLocation operandLocation = new OperandFieldLocation(program, addr("0100416c"),
			null, addr("0x8"), operandPrefix + operandReferenceName, 1, 9);
		codeBrowser.goTo(operandLocation);
		waitForSwing();

		ProgramLocation currentLocation = codeBrowser.getCurrentLocation();
		assertTrue(currentLocation instanceof OperandFieldLocation);
		assertEquals(operandLocation.getAddress(), currentLocation.getAddress());
	}

	@Test
	public void testFunctionNavigation_ExternalProgramFunction_OptionNavigateToExternal()
			throws Exception {

		// this call triggers jMockit to load our spy
		new SpyGoToHelper();

		tool.getOptions("Navigation")
				.setEnum("External Navigation",
					NavigationOptions.ExternalNavigationEnum.NavigateToExternalProgram);

		//
		// Take an existing function with a call reference and change it to call a thunk with
		// an external program reference.
		//

		/*
		 	01005a32 e8 be d2    CALL ghidra 
		             ff ff
		 */

		String thunkAddress = "1002cf5";  // function 'ghidra'
		createThunkToExternal(thunkAddress);

		decompile("10059a3"); // function that calls 'ghidra' 

		int line = 35;
		int character = 1;
		assertToken("ghidra", line, character);
		setDecompilerLocation(line, character);
		doubleClick();

		assertExternalNavigationPerformed();
		assertNotEquals(thunkAddress, codeBrowser.getCurrentAddress());
	}

	@Test
	public void testFunctionNavigation_ExternalProgramFunction_OptionNavigateToLinkage()
			throws Exception {

		// this call triggers jMockit to load our spy
		new SpyGoToHelper();

		tool.getOptions("Navigation")
				.setEnum("External Navigation",
					NavigationOptions.ExternalNavigationEnum.NavigateToLinkage);

		//
		// Take an existing function with a call reference and change it to call a thunk with
		// an external program reference.
		//

		/*
		 	01005a32 e8 be d2    CALL ghidra 
		             ff ff
		 */

		String thunkAddress = "1002cf5";  // function 'ghidra'
		createThunkToExternal(thunkAddress);

		decompile("10059a3"); // function that calls 'ghidra' 

		int line = 35;
		int character = 1;
		assertToken("ghidra", line, character);
		setDecompilerLocation(line, character);
		doubleClick();

		assertExternalNavigationNotPerformed();
		assertEquals(addr(thunkAddress), codeBrowser.getCurrentAddress());
	}

	@Test
	public void testSingleClickingFunctionCallDoesNotMoveListingToThatFunction() {

		decompile("1002cf5"); // 'ghidra'

		// 22: FUN_01002c93(param_3,param_4,iVar1);
		int line = 22;
		int character = 5;
		assertToken("FUN_01002c93", line, character);
		setDecompilerLocation(line, character);

		// this is the address within the function of the call to the function we clicked
		assertListingAddress(addr("01002d32"));
	}

	@Test
	public void testFunctionNavigation_WithAViewThatCachesTheLastValidFunction()
			throws Exception {

		//
		// This is testing the case where the user starts on a function foo().  Ancillary windows
		// will display tool, such as a decompiled view.   Now, if the user clicks to a 
		// non-function location, such as data, the ancillary window may still show foo(), even 
		// though the user is no longer in foo.  At this point, if the user wishes to go to the
		// previous function, then from the ancillary window's perspective, it is the function 
		// that came before foo().
		//

		Address f1 = addr("01002cf5"); // ghidra
		Address f2 = addr("0100415a"); // sscanf
		Address nonFunctionAddress = addr("01001000");

		goTo(f1);
		goTo(f2);
		goTo(nonFunctionAddress);

		String title = provider.getTitle();
		assertTrue("Decompiler did not retain last function visited", title.contains("sscanf"));

		provider.requestFocus();
		waitForSwing();

		// 
		// The Decompiler is focused, showing 'entry'.  Going back while it is focused should go
		// to the function before 'entry', which is 'ghidra'.
		//
		previousFunction();
		assertCurrentAddress(f1);
	}

	private void previousFunction() {
		NextPrevAddressPlugin plugin = env.getPlugin(NextPrevAddressPlugin.class);
		DockingAction previousFunctionAction =
			(DockingAction) getInstanceField("previousFunctionAction", plugin);

		ActionContext context = provider.getActionContext(null);
		assertTrue(previousFunctionAction.isEnabledForContext(context));
		performAction(previousFunctionAction, context, true);
		waitForSwing();
	}

	private void assertListingAddress(Address expected) {
		waitForCondition(() -> expected.equals(codeBrowser.getCurrentLocation().getAddress()),
			"The Listing is not at the expected address");
	}

	@Override
	public void assertCurrentAddress(Address expected) {
		codeBrowser.updateNow();
		waitForSwing();

		waitForCondition(() -> {
			ProgramLocation loc = codeBrowser.getCurrentLocation();
			Address actual = loc.getAddress();
			return expected.equals(actual);
		}, "Listing is not at the expected address");
	}

	private void assertExternalNavigationPerformed() {
		// going to the 'external linkage' means we went to the thunk function and not the
		// external program
		assertFalse("External navigation did not take place", goToExternalLinkageCalled);
	}

	private void assertExternalNavigationNotPerformed() {
		// going to the 'external linkage' means we went to the thunk function and not the
		// external program
		assertTrue("External navigation should not have taken place", goToExternalLinkageCalled);
	}

	private void createThunkToExternal(String addressString) throws Exception {

		int txId = program.startTransaction("Set External Location");
		try {

			program.getExternalManager().setExternalPath("ADVAPI32.dll", "/FILE1", true);

			Address address = addr(addressString);
			CreateFunctionCmd cmd = new CreateFunctionCmd(address);
			cmd.applyTo(program);

			String extAddress = "0x1001000";
			ExternalManager em = program.getExternalManager();

			// "ADVAPI32.dll", "externalFunctionXyz", "_Zxyz"
			ExternalLocation externalLocation =
				em.addExtFunction(Library.UNKNOWN, "_Zxyz", addr(extAddress), SourceType.IMPORTED);
			Library lib = em.addExternalLibraryName("ADVAPI32.dll", SourceType.IMPORTED);
			externalLocation.setName(lib, "externalFunctionXyz", SourceType.IMPORTED);

			Function function = program.getFunctionManager().getFunctionAt(addr(addressString));
			function.setThunkedFunction(externalLocation.getFunction());
		}
		finally {
			program.endTransaction(txId, true);
		}

		program.flushEvents();
		waitForSwing();
	}

	public class SpyGoToHelper extends MockUp<GoToHelper> {

		@Mock
		private boolean goToExternalLinkage(Invocation invocation, Navigatable nav,
				ExternalLocation externalLoc, boolean popupAllowed) {

			goToExternalLinkageCalled = true;
			return invocation.proceed(nav, externalLoc, popupAllowed);
		}
	}
}
