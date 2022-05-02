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
package ghidra.app.plugin.core.assembler;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Objects;

import javax.swing.JTextField;

import docking.test.AbstractDockingTest;
import generic.test.AbstractGTest;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.AssemblyCompletion;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.AssemblyInstruction;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class AssemblerPluginTestHelper {
	public final AssemblerPlugin assemblerPlugin;
	private final CodeViewerProvider provider;
	private final Program program;

	public final PatchInstructionAction patchInstructionAction;
	public final PatchDataAction patchDataAction;
	public final AssemblyDualTextField instructionInput;
	public final JTextField dataInput;

	private final Listing listing;

	public AssemblerPluginTestHelper(AssemblerPlugin assemblerPlugin, CodeViewerProvider provider,
			Program program) {
		this.assemblerPlugin = assemblerPlugin;
		this.provider = provider;
		this.program = program;

		this.patchInstructionAction = assemblerPlugin.patchInstructionAction;
		this.patchDataAction = assemblerPlugin.patchDataAction;
		this.instructionInput = assemblerPlugin.patchInstructionAction.input;
		this.dataInput = assemblerPlugin.patchDataAction.input;
		this.listing = program.getListing();

		// Snuff the assembler's warning prompt
		patchInstructionAction.shownWarning.put(program.getLanguage(), true);
	}

	public void assertDualFields() {
		assertFalse(instructionInput.getAssemblyField().isVisible());
		assertTrue(instructionInput.getMnemonicField().isVisible());
		assertTrue(instructionInput.getOperandsField().isVisible());
	}

	public List<AssemblyCompletion> inputAndGetCompletions(String text) {
		return AbstractGenericTest.runSwing(() -> {
			instructionInput.setText(text);
			instructionInput.auto.startCompletion(instructionInput.getOperandsField());
			instructionInput.auto.flushUpdates();
			return instructionInput.auto.getSuggestions();
		});
	}

	public void goTo(Address address) {
		ListingPanel listingPanel = provider.getListingPanel();
		ProgramLocation location = new ProgramLocation(program, address);
		AbstractGTest.waitForCondition(() -> {
			AbstractGenericTest.runSwing(() -> listingPanel.goTo(location));
			ProgramLocation confirm = listingPanel.getCursorLocation();
			if (confirm == null) {
				return false;
			}
			if (!address.equals(confirm.getAddress())) {
				return false;
			}
			return true;
		});
	}

	public Instruction patchInstructionAt(Address address, String expText, String newText) {
		goTo(address);

		AbstractDockingTest.performAction(assemblerPlugin.patchInstructionAction, provider, true);
		assertDualFields();
		assertEquals(expText, instructionInput.getText());
		assertEquals(address, assemblerPlugin.patchInstructionAction.getAddress());

		List<AssemblyCompletion> completions = inputAndGetCompletions(newText);
		AssemblyCompletion first = completions.get(0);
		assertTrue(first instanceof AssemblyInstruction);
		AssemblyInstruction ai = (AssemblyInstruction) first;

		AbstractGenericTest.runSwing(() -> assemblerPlugin.patchInstructionAction.accept(ai));
		AbstractGhidraHeadedIntegrationTest.waitForProgram(program);

		return Objects.requireNonNull(listing.getInstructionAt(address));
	}

	public Data patchDataAt(Address address, String expText, String newText) {
		goTo(address);

		AbstractDockingTest.performAction(assemblerPlugin.patchDataAction, provider, true);
		assertTrue(dataInput.isVisible());
		assertEquals(expText, dataInput.getText());
		assertEquals(address, assemblerPlugin.patchDataAction.getAddress());

		AbstractGenericTest.runSwing(() -> {
			dataInput.setText(newText);
			assemblerPlugin.patchDataAction.accept();
		});
		AbstractGhidraHeadedIntegrationTest.waitForProgram(program);

		return Objects.requireNonNull(listing.getDataAt(address));
	}
}
