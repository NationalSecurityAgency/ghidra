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

import java.awt.Font;
import java.awt.event.FocusListener;
import java.awt.event.KeyListener;
import java.util.HashMap;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.KeyStroke;

import org.apache.commons.collections4.map.DefaultedMap;
import org.apache.commons.collections4.map.LazyMap;

import db.Transaction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.autocomplete.*;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.CachingSwingWorker;
import ghidra.util.task.TaskMonitor;

/**
 * A context menu action to assemble an instruction at the current address
 */
public class PatchInstructionAction extends AbstractPatchAction {

	/**
	 * Enumerated quality ratings and text to describe them.
	 */
	static enum AssemblyRating {
		UNRATED("This processor has not been tested with the assembler." +
			" The assembler will probably work on this language."),
		POOR("This processor received a rating of POOR during testing." +
			" We DO NOT recommend trying to assemble."),
		BRONZE("This processor received a rating of BRONZE during testing." +
			" A fair number of instructions may assemble, but we DO NOT recommend trying to" +
			" assemble."),
		SILVER("This processor received a rating of SILVER during testing." +
			" Most instructions should work, but you will likely encounter a few errors."),
		GOLD("This processor received a rating of GOLD during testing." +
			" You should rarely encounter an error."),
		PLATINUM("This processor received a rating of PLATINUM during testing.");

		final String message;

		private AssemblyRating(String message) {
			this.message = message;
		}
	}

	// To build the assembler in the background if it takes a while
	private static class AssemblerConstructorWorker extends CachingSwingWorker<Assembler> {
		private Language language;

		public AssemblerConstructorWorker(Language language) {
			super("Assemble", false);
			this.language = language;
		}

		@Override
		protected Assembler runInBackground(TaskMonitor monitor) {
			monitor.setMessage("Constructing assembler for " + language);
			return Assemblers.getAssembler(language);
		}
	}

	private static final String ASSEMBLY_RATING = "assemblyRating";
	private static final String ASSEMBLY_MESSAGE = "assemblyMessage";
	private static final KeyStroke KEYBIND_PATCH_INSTRUCTION =
		KeyStroke.getKeyStroke("ctrl shift G");

	/**
	 * A listener for activation of a completion item
	 *
	 * <p>
	 * The {@link AbstractPatchAction#accept()} method does not suffice for this action, since one
	 * of the suggested byte sequences must be selected, as presented by the completer. Thus, we'll
	 * nop that method, and instead call our own acceptance logic from here.
	 */
	private class ListenerForAccept implements AutocompletionListener<AssemblyCompletion> {
		@Override
		public void completionActivated(AutocompletionEvent<AssemblyCompletion> ev) {
			if (ev.getSelection() instanceof AssemblyInstruction) {
				AssemblyInstruction ins = (AssemblyInstruction) ev.getSelection();
				accept(ins);
			}
		}
	}

	private final Map<Language, CachingSwingWorker<Assembler>> cache =
		LazyMap.lazyMap(new HashMap<>(), language -> new AssemblerConstructorWorker(language));

	/*test*/ static final Map<Language, Boolean> SHOWN_WARNING =
		DefaultedMap.defaultedMap(new HashMap<>(), false);

	/*test*/ final AssemblyDualTextField input = newAssemblyDualTextField();
	private final ListenerForAccept listenerForAccept = new ListenerForAccept();

	protected Language language;
	protected Assembler assembler;

	// Callback to keep the autocompleter positioned under the fields
	private FieldPanelOverLayoutListener listenerToMoveAutocompleter = ev -> {
		TextFieldAutocompleter<AssemblyCompletion> autocompleter = input.getAutocompleter();
		if (autocompleter.isCompletionListVisible()) {
			autocompleter.updateDisplayLocation();
		}
	};

	public PatchInstructionAction(Plugin owner) {
		this(owner, "Patch Instruction");
	}

	public PatchInstructionAction(Plugin owner, String name) {
		super(owner, name);

		setPopupMenuData(new MenuData(new String[] { name }, MENU_GROUP));
		setKeyBindingData(new KeyBindingData(KEYBIND_PATCH_INSTRUCTION));
		setHelpLocation(new HelpLocation(owner.getName(), "patch_instruction"));

		input.getMnemonicField().setBorder(BorderFactory.createLineBorder(Colors.ERROR, 2));
		input.getOperandsField().setBorder(BorderFactory.createLineBorder(Colors.ERROR, 2));
		input.getAssemblyField().setBorder(BorderFactory.createLineBorder(Colors.ERROR, 2));

		input.getAutocompleter().addAutocompletionListener(listenerForAccept);

		init();
	}

	protected AssemblyDualTextField newAssemblyDualTextField() {
		return new AssemblyDualTextField();
	}

	@Override
	public void dispose() {
		super.dispose();
		input.dispose();
	}

	@Override
	protected void addInputFocusListener(FocusListener listener) {
		input.addFocusListener(listener);
	}

	@Override
	protected void addInputKeyListener(KeyListener listener) {
		input.addKeyListener(listener);
	}

	@Override
	protected void addLayoutListeners(FieldPanelOverLayoutManager fieldLayoutManager) {
		fieldLayoutManager.addLayoutListener(listenerToMoveAutocompleter);
	}

	@Override
	protected void removeLayoutListeners(FieldPanelOverLayoutManager fieldLayoutManager) {
		fieldLayoutManager.removeLayoutListener(listenerToMoveAutocompleter);
	}

	@Override
	protected boolean isApplicableToUnit(CodeUnit cu) {
		return true;
	}

	protected void warnLanguage() {
		AssemblyRating rating = AssemblyRating.valueOf(
			language.getProperty(ASSEMBLY_RATING + ":" + language.getLanguageID(),
				AssemblyRating.UNRATED.name()));
		if (AssemblyRating.PLATINUM != rating) {
			String message = language.getProperty(ASSEMBLY_MESSAGE + ":" + language.getLanguageID(),
				rating.message);
			if (!SHOWN_WARNING.get(language)) {
				Msg.showWarn(this, null, "Assembler Rating",
					"<html><body><p style='width: 300px;'>" + message + "</p></body></html>");
				SHOWN_WARNING.put(language, true);
			}
		}
	}

	protected Language getLanguage(CodeUnit cu) {
		return cu.getProgram().getLanguage();
	}

	protected Assembler getAssembler(CodeUnit cu) {
		return Assemblers.getAssembler(cu.getProgram());
	}

	@Override
	protected void prepare() {
		CodeUnit cu = getCodeUnit();
		language = getLanguage(cu);
		warnLanguage();
		cache.get(language).get(null);
		assembler = getAssembler(cu);
	}

	@Override
	protected void setInputFont(Font font) {
		input.setFont(font);
	}

	protected Instruction getExistingInstruction() {
		Program program = getProgram();
		if (program == null) {
			return null;
		}
		return program.getListing().getInstructionAt(getAddress());
	}

	@Override
	protected boolean showInputs(FieldPanel fieldPanel) {
		input.setAssembler(assembler);
		input.setAddress(getAddress());
		input.setExisting(getExistingInstruction());
		FieldLocation locMnem = findFieldLocation(getAddress(), "Mnemonic");
		if (locMnem == null) {
			Msg.showError(this, fieldPanel, getName(),
				"The Mnemonic field must be present to patch instruction");
			return false;
		}
		FieldLocation locOpns = findFieldLocation(getAddress(), "Operands");
		if (locOpns == null) {
			// Use the single-box variant
			fieldPanel.add(input.getAssemblyField(), locMnem);
			input.setVisible(VisibilityMode.SINGLE_VISIBLE);
		}
		else {
			// Use the split variant
			fieldPanel.add(input.getMnemonicField(), locMnem);
			fieldPanel.add(input.getOperandsField(), locOpns);
			input.setVisible(VisibilityMode.DUAL_VISIBLE);
		}
		return true;
	}

	@Override
	protected void fillInputs() {
		CodeUnit cu = getCodeUnit();
		if (cu instanceof Instruction) {
			Instruction ins = (Instruction) cu;
			String instr = ins.toString();
			if (ins.isInDelaySlot()) {
				assert instr.startsWith("_");
				instr = instr.substring(1).trim();
			}
			input.setText(instr);
			input.setCaretPosition(instr.length());
			if (input.getVisible() == VisibilityMode.SINGLE_VISIBLE) {
				input.getAssemblyField().grabFocus();
			}
			else if (instr.contains(" ")) {
				input.getOperandsField().grabFocus();
			}
			else {
				input.getMnemonicField().grabFocus();
			}
		}
		else {
			input.setText("");
			input.setCaretPosition(0);
			if (input.getVisible() == VisibilityMode.SINGLE_VISIBLE) {
				input.getAssemblyField().grabFocus();
			}
			else {
				input.getMnemonicField().grabFocus();
			}
		}
	}

	@Override
	public void accept() {
		// Do nothing. User must select a completion item instead
	}

	protected void applyPatch(byte[] data) throws MemoryAccessException {
		assembler.patchProgram(data, getAddress());
	}

	/**
	 * Accept the given instruction selected by the user
	 * 
	 * @param ins the selected instruction from the completion list
	 */
	public void accept(AssemblyInstruction ins) {
		Program program = getProgram();
		Address address = getAddress();
		try (Transaction tx =
			program.openTransaction("Assemble @" + address + ": " + input.getText())) {
			applyPatch(ins.getData());
			hide();
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Assemble", "Could not patch selected instruction", e);
		}
	}
}
