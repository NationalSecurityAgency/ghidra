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

import javax.swing.JTextField;

import docking.test.AbstractDockingTest;
import generic.test.AbstractGTest;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.AssemblyCompletion;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.AssemblyInstruction;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class AssemblerPluginTestHelper {
	private final CodeViewerProvider provider;
	private final Program program;

	public final PatchInstructionAction patchInstructionAction;
	public final PatchDataAction patchDataAction;
	public final AssemblyDualTextField instructionInput;
	public final JTextField dataInput;

	private final Listing listing;

	public AssemblerPluginTestHelper(PatchInstructionAction patchInstructionAction,
			PatchDataAction patchDataAction, CodeViewerProvider provider, Program program) {
		this.provider = provider;
		this.program = program;

		this.patchInstructionAction = patchInstructionAction;
		this.patchDataAction = patchDataAction;
		this.instructionInput =
			patchInstructionAction == null ? null : patchInstructionAction.input;
		this.dataInput = patchDataAction == null ? null : patchDataAction.input;
		this.listing = program.getListing();

		// Snuff the assembler's warning prompt
		snuffWarning(program.getLanguage());
	}

	public AssemblerPluginTestHelper(AssemblerPlugin assemblerPlugin, CodeViewerProvider provider,
			Program program) {
		this(assemblerPlugin.patchInstructionAction, assemblerPlugin.patchDataAction, provider,
			program);
	}

	public void snuffWarning(Language language) {
		PatchInstructionAction.SHOWN_WARNING.put(language, true);
	}

	public void assertDualFields() {
		assertFalse(instructionInput.getAssemblyField().isVisible());
		assertTrue(instructionInput.getMnemonicField().isVisible());
		assertTrue(instructionInput.getOperandsField().isVisible());
	}

	public List<AssemblyCompletion> inputAndGetCompletions(String text) {
		AbstractGenericTest.runSwing(() -> {
			instructionInput.setText(text);
			JTextField field = instructionInput.getOperandsField();
			instructionInput.auto.fakeFocusGained(field);
			instructionInput.auto.startCompletion(field);
			instructionInput.auto.updateNow();
		});
		return AbstractGenericTest.waitForValue(() -> AbstractGenericTest.runSwing(() -> {
			List<AssemblyCompletion> suggestions = instructionInput.auto.getSuggestions();
			if (suggestions.isEmpty()) {
				return null;
			}
			return suggestions;
		}));
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
		Language language = patchInstructionAction.getLanguage(listing.getCodeUnitAt(address));
		snuffWarning(language);

		AbstractDockingTest.performAction(patchInstructionAction, provider, true);
		assertDualFields();
		assertEquals(expText, instructionInput.getText());
		assertEquals(address, patchInstructionAction.getAddress());

		List<AssemblyCompletion> completions = inputAndGetCompletions(newText);
		assertFalse("There are no assembly completion options", completions.isEmpty());
		AssemblyCompletion first = completions.get(0);
		assertTrue(first instanceof AssemblyInstruction);
		AssemblyInstruction ai = (AssemblyInstruction) first;

		AbstractGenericTest.runSwing(() -> patchInstructionAction.accept(ai));
		AbstractGhidraHeadedIntegrationTest.waitForProgram(program);

		return AbstractGTest.waitForValue(() -> listing.getInstructionAt(address));
	}

	public Data patchDataAt(Address address, String expText, String newText) {
		goTo(address);

		AbstractDockingTest.performAction(patchDataAction, provider, true);
		assertTrue(dataInput.isVisible());
		assertEquals(expText, dataInput.getText());
		assertEquals(address, patchDataAction.getAddress());

		AbstractGenericTest.runSwing(() -> {
			dataInput.setText(newText);
			patchDataAction.accept();
		});
		AbstractGhidraHeadedIntegrationTest.waitForProgram(program);

		return AbstractGTest.waitForValue(() -> listing.getDataAt(address));
	}
}
