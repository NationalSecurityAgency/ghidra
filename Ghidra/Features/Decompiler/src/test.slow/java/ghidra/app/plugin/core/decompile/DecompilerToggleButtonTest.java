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

import org.junit.After;
import org.junit.Test;

import docking.action.ToggleDockingActionIf;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class DecompilerToggleButtonTest extends AbstractDecompilerTest {

	private Program prog;

	@Override
	@After
	public void tearDown() throws Exception {
		super.tearDown();
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	private Program buildProgram() throws Exception {

		/*
		int b = 1;
		
		int readB(){
			return b;
		}
		
		int main()
		{
			int a = 5;
		
			a++;
			
			if (a > 4)
			{
				a = 0;
			}
			else
			{
				a = readB();
			}
			
			return a;
		}
		 */

		ProgramBuilder builder =
			new ProgramBuilder("TestDecompilerToggleButtons", ProgramBuilder._X64);

		// Create the global "b" variable
		MemoryBlock bVarBlock = builder.createMemory("bVarBl", "0x104010", 4);
		builder.setWrite(bVarBlock, false);
		builder.createLabel("0x104010", "b");
		builder.setBytes("0x104010", "01 00 00 00");

		// Create the "readB" function
		MemoryBlock readBFunctionBlock = builder.createMemory("readBFunction", "0x101129", 16);
		builder.setWrite(readBFunctionBlock, false);
		builder.setBytes("0x101129", "f3 0f 1e fa 55 48 89 e5 8b 05 d9 2e 00 00 5d c3");
		builder.createFunction("0x101129");
		builder.createLabel("0x101129", "readB");

		// Create the "main" function
		MemoryBlock mainFunctionBlock = builder.createMemory("mainFunction", "0x101139", 56);
		builder.setWrite(mainFunctionBlock, false);
		builder.setBytes("0x101139",
			"f3 0f 1e fa 55 48 89 e5 48 83 ec 10 c7 45 fc 05 00 00 00 83 45 fc 01 83 7d fc 04 7e " +
				"09 c7 45 fc 00 00 00 00 eb 0d b8 00 00 00 00 e8 c0 ff ff ff 89 45 fc 8b 45 fc c9 c3");
		builder.createFunction("0x101139");
		builder.createLabel("0x101129", "main");

		builder.analyze();

		prog = builder.getProgram();

		return prog;
	}

	@Test
	public void testUnreachableCodeToggle() {

		DecompilerController controller = provider.getController();

		// Point the decompiler at the "main" function
		decompile("0x101139");
		waitForSwing();

		// Get the decompiled program as a C code string
		String resultingC = getResultingCCode(controller);

		// Check that the resulting decompilation does NOT contain unreachable code
		assertNotNull(resultingC);
		assertNotEquals("", resultingC);
		assertTrue(resultingC.contains("WARNING: Removing unreachable block"));

		ToggleDockingActionIf eliminateUnreachableToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Unreachable Code");

		// Check button state - should not be pressed down
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertFalse(eliminateUnreachableToggleAction.isSelected());

		// Toggle unreachable code
		performAction(eliminateUnreachableToggleAction, provider.getActionContext(null), false);
		waitForDecompiler();

		// Get the decompiled program as a C code string
		resultingC = getResultingCCode(controller);

		// Check that the resulting decompilation now contains unreachable code
		assertNotNull(resultingC);
		assertNotEquals("", resultingC);
		assertFalse(resultingC.contains("WARNING: Removing unreachable block"));

		// Check button state - should be pressed down (with slash)
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertTrue(eliminateUnreachableToggleAction.isSelected());

	}

	@Test
	public void testReadOnlyCodeToggle() {

		DecompilerController controller = provider.getController();

		// Point the decompiler at the "readB" function
		decompile("0x101129");
		waitForSwing();

		// Get the decompiled program as a C code string
		String resultingC = getResultingCCode(controller);

		// Check that the resulting decompilation does NOT respect read-only flags
		assertNotNull(resultingC);
		assertNotEquals("", resultingC);
		assertTrue(resultingC.contains("return 1;"));

		ToggleDockingActionIf respectReadonlyToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Respecting Read-only Flags");

		// Check button state - should not be pressed down
		assertTrue(respectReadonlyToggleAction.isEnabled());
		assertFalse(respectReadonlyToggleAction.isSelected());

		// Toggle read-only code visibility
		performAction(respectReadonlyToggleAction, provider.getActionContext(null), false);
		waitForDecompiler();

		// Get the decompiled program as a C code string
		resultingC = getResultingCCode(controller);

		// Check that the resulting decompilation now respects read-only flags
		assertNotNull(resultingC);
		assertNotEquals("", resultingC);
		assertTrue(resultingC.contains("return b;"));

		// Check button state - should be pressed down (with slash)
		assertTrue(respectReadonlyToggleAction.isEnabled());
		assertTrue(respectReadonlyToggleAction.isSelected());

	}

	@Test
	public void unreachableCodeToggleDoesNotUpdateOptions() {

		// Point the decompiler at the "main" function
		decompile("0x101139");
		waitForSwing();

		ToggleDockingActionIf eliminateUnreachableToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Unreachable Code");

		// Check button state - should not be pressed down
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertFalse(eliminateUnreachableToggleAction.isSelected());

		// Get the (currently default) options
		DecompileOptions decompilerOptions = getOptions();

		// Check default state to be eliminating unreachable code
		assertTrue(decompilerOptions.isEliminateUnreachable());

		// Toggle unreachable code
		performAction(eliminateUnreachableToggleAction, provider.getActionContext(null), false);
		waitForDecompiler();

		// Grab new options - should be the same as before
		decompilerOptions = getOptions();
		assertTrue(decompilerOptions.isEliminateUnreachable());
	}

	@Test
	public void buttonsResetOnOptionChange() {

		// Point the decompiler at the "main" function
		decompile("0x101139");
		waitForSwing();

		ToggleDockingActionIf eliminateUnreachableToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Unreachable Code");

		// Check button state - should not be pressed down
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertFalse(eliminateUnreachableToggleAction.isSelected());

		// Get the (currently default) options
		DecompileOptions decompilerOptions = getOptions();

		// Check default state to be eliminating unreachable code
		assertTrue(decompilerOptions.isEliminateUnreachable());

		// Set the option to be false (should update the toggle button)
		setEliminateUnreachable(false);

		// The button state and decompiler options should have updated automatically
		decompilerOptions = getOptions();
		assertFalse(decompilerOptions.isEliminateUnreachable());

		// Check button state - should be pressed down (with slash)
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertTrue(eliminateUnreachableToggleAction.isSelected());
	}

	@Test
	public void buttonStatesRemainOnFunctionSwitch() {

		// Point the decompiler at the "main" function
		decompile("0x101139");
		waitForSwing();

		ToggleDockingActionIf eliminateUnreachableToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Unreachable Code");
		ToggleDockingActionIf respectReadonlyToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Respecting Read-only Flags");

		// Check button state - should not be pressed down
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertFalse(eliminateUnreachableToggleAction.isSelected());
		assertTrue(respectReadonlyToggleAction.isEnabled());
		assertFalse(respectReadonlyToggleAction.isSelected());

		// Toggle unreachable code
		performAction(eliminateUnreachableToggleAction, provider.getActionContext(null), false);
		waitForDecompiler();

		// Toggle respecting read-only flags
		performAction(respectReadonlyToggleAction, provider.getActionContext(null), false);
		waitForDecompiler();

		// Check button state - should be pressed down (with slash)
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertTrue(eliminateUnreachableToggleAction.isSelected());
		assertTrue(respectReadonlyToggleAction.isEnabled());
		assertTrue(respectReadonlyToggleAction.isSelected());

		// Switch functions
		// Point the decompiler at the "readB" function
		decompile("0x101129");
		waitForSwing();

		// Check button state - should be pressed down (with slash)
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertTrue(eliminateUnreachableToggleAction.isSelected());
		assertTrue(respectReadonlyToggleAction.isEnabled());
		assertTrue(respectReadonlyToggleAction.isSelected());

	}

	@Test
	public void buttonStatesUpdateWhenHidden() {

		// Point the decompiler at the "main" function
		decompile("0x101139");
		waitForSwing();

		ToggleDockingActionIf eliminateUnreachableToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Unreachable Code");

		// Check button state - should not be pressed down
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertFalse(eliminateUnreachableToggleAction.isSelected());

		// Hide the decompiler panel
		tool.showComponentProvider(provider, false);
		waitForSwing();

		// Change the option to a non-default state
		setEliminateUnreachable(false);

		// Show the decompiler panel
		tool.showComponentProvider(provider, true);
		waitForSwing();

		// Check button state - should not be pressed down
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertTrue(eliminateUnreachableToggleAction.isSelected());
	}

	@Test
	public void buttonStatesResetOnReopen() {

		// Point the decompiler at the "main" function
		decompile("0x101139");
		waitForSwing();

		ToggleDockingActionIf eliminateUnreachableToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Unreachable Code");
		ToggleDockingActionIf respectReadonlyToggleAction =
			(ToggleDockingActionIf) getAction(decompiler, "Toggle Respecting Read-only Flags");

		// Check button state - should not be pressed down
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertFalse(eliminateUnreachableToggleAction.isSelected());
		assertTrue(respectReadonlyToggleAction.isEnabled());
		assertFalse(respectReadonlyToggleAction.isSelected());

		// Toggle unreachable code
		performAction(eliminateUnreachableToggleAction, provider.getActionContext(null), false);
		waitForDecompiler();

		// Toggle respecting read-only flags
		performAction(respectReadonlyToggleAction, provider.getActionContext(null), false);
		waitForDecompiler();

		// Check button state - should be pressed down (with slash)
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertTrue(eliminateUnreachableToggleAction.isSelected());
		assertTrue(respectReadonlyToggleAction.isEnabled());
		assertTrue(respectReadonlyToggleAction.isSelected());

		// Hide the decompiler panel
		tool.showComponentProvider(provider, false);
		waitForSwing();

		// Show the decompiler panel
		tool.showComponentProvider(provider, true);
		waitForSwing();

		// Check button states - should have reset to tool option state
		assertTrue(eliminateUnreachableToggleAction.isEnabled());
		assertFalse(eliminateUnreachableToggleAction.isSelected());
		assertTrue(respectReadonlyToggleAction.isEnabled());
		assertFalse(respectReadonlyToggleAction.isSelected());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private String getResultingCCode(DecompilerController controller) {
		return controller.getDecompileData().getDecompileResults().getDecompiledFunction().getC();
	}

	private DecompileOptions getOptions() {
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		ToolOptions opt = tool.getOptions("Decompiler");

		DecompileOptions decompilerOptions = new DecompileOptions();
		decompilerOptions.registerOptions(fieldOptions, opt, program);
		return decompilerOptions;
	}

	private void setEliminateUnreachable(boolean enabled) {
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		ToolOptions opt = tool.getOptions("Decompiler");

		opt.getOptions("Analysis").setBoolean("Eliminate unreachable code", enabled);

		DecompileOptions decompilerOptions = new DecompileOptions();
		decompilerOptions.registerOptions(fieldOptions, opt, program);
	}

}
