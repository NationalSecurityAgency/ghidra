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

import java.awt.Color;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.KeyStroke;

import org.apache.commons.collections4.map.DefaultedMap;
import org.apache.commons.collections4.map.LazyMap;

import docking.*;
import docking.action.*;
import docking.widgets.autocomplete.*;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.*;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.listingpanel.ListingModelAdapter;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.util.ProgramTransaction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.CachingSwingWorker;
import ghidra.util.task.TaskMonitor;

/**
 * A context menu action to assemble an instruction at the current address
 */
public class AssembleDockingAction extends DockingAction {
	private static final String ASSEMBLY_RATING = "assemblyRating";
	private static final String ASSEMBLY_MESSAGE = "assemblyMessage";
	private static final KeyStroke KEYBIND_ASSEMBLE = KeyStroke.getKeyStroke(KeyEvent.VK_G,
		DockingUtils.CONTROL_KEY_MODIFIER_MASK | InputEvent.SHIFT_DOWN_MASK);
	//private PluginTool tool;
	private FieldPanelOverLayoutManager fieldLayoutManager;
	private CodeViewerProvider cv;
	private FieldPanel codepane;
	private ListingPanel listpane;
	private Map<Language, CachingSwingWorker<Assembler>> cache =
		LazyMap.lazyMap(new HashMap<>(), language -> new AssemblerConstructorWorker(language));

	private Map<Language, Boolean> shownWarning = DefaultedMap.defaultedMap(new HashMap<>(), false);

	private final AssemblyDualTextField input = new AssemblyDualTextField();
	private Program prog;
	private Address addr;
	private Language lang;
	private Assembler assembler;
	private final MyListener listener = new MyListener();
	//private PluginTool tool;

	// Callback to keep the autocompleter positioned under the fields
	private FieldPanelOverLayoutListener autoCompleteMover = (FieldPanelOverLayoutEvent ev) -> {
		TextFieldAutocompleter<AssemblyCompletion> autocompleter = input.getAutocompleter();
		if (autocompleter.isCompletionListVisible()) {
			autocompleter.updateDisplayLocation();
		}
	};

	// To build the assembler in the background if it takes a while
	private static class AssemblerConstructorWorker extends CachingSwingWorker<Assembler> {
		private Language lang;

		public AssemblerConstructorWorker(Language lang) {
			super("Assemble", false);
			this.lang = lang;
		}

		@Override
		protected Assembler runInBackground(TaskMonitor monitor) {
			monitor.setMessage("Constructing assembler for " + lang);
			return Assemblers.getAssembler(lang);
		}
	}

	/*
	 * A class for all my callbacks
	 * 
	 * For autocompletion, this causes activation of an assembled instruction to actually patch the
	 * instruction in.
	 * 
	 * For keyboard, it causes the escape key, if not already consumed by the autocompleter, to
	 * cancel the assembly action altogether.
	 */
	private class MyListener implements AutocompletionListener<AssemblyCompletion>, KeyListener {
		@Override
		public void completionActivated(AutocompletionEvent<AssemblyCompletion> ev) {
			if (ev.getSelection() instanceof AssemblyInstruction) {
				AssemblyInstruction ins = (AssemblyInstruction) ev.getSelection();
				try (ProgramTransaction trans =
					ProgramTransaction.open(prog, "Assemble @" + addr + ": " + input.getText())) {
					assembler.patchProgram(ins.getData(), addr);
					trans.commit();
					cancel(); // Not really, since I've committed. Just hides the editors.
					return;
				}
				catch (MemoryAccessException e) {
					Msg.showError(assembler, input.getMnemonicField().getRootPane(), "Assemble",
						"Could not patch selected instruction", e);
				}
			}
		}

		@Override
		public void keyTyped(KeyEvent e) {
			// Blank
		}

		@Override
		public void keyPressed(KeyEvent e) {
			if (e.isConsumed()) {
				return;
			}
			if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
				cancel();
				e.consume();
			}
		}

		@Override
		public void keyReleased(KeyEvent e) {
			// Blank
		}
	}

	public AssembleDockingAction(PluginTool tool, String name, String owner) {
		this(name, owner);
		//this.tool = tool;

		// If I lose focus, cancel the assembly
		input.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// Blank
			}

			@Override
			public void focusLost(FocusEvent e) {
				cancel();
			}
		});

		input.getMnemonicField().setBorder(BorderFactory.createLineBorder(Color.RED, 2));
		input.getOperandsField().setBorder(BorderFactory.createLineBorder(Color.RED, 2));
		input.getAssemblyField().setBorder(BorderFactory.createLineBorder(Color.RED, 2));

		input.getAutocompleter().addAutocompletionListener(listener);
		input.addKeyListener(listener);
	}

	@Override
	public void dispose() {
		super.dispose();
		input.dispose();
	}

	protected void prepareLayout(ActionContext context) {
		ComponentProvider prov = context.getComponentProvider();
		if (cv == prov) {
			return;
		}

		if (cv != null) {
			codepane.setLayout(null);
			fieldLayoutManager.removeLayoutListener(autoCompleteMover);
		}

		// we are only added to the popup for a ListingActionContext that has a CodeViewerProvider
		cv = (CodeViewerProvider) prov;
		listpane = cv.getListingPanel();
		codepane = listpane.getFieldPanel();

		fieldLayoutManager = new FieldPanelOverLayoutManager(codepane);
		codepane.setLayout(fieldLayoutManager);
		fieldLayoutManager.addLayoutListener(autoCompleteMover);
	}

	/**
	 * Cancel the current assembly action
	 */
	public void cancel() {
		codepane.removeAll();
		//codepane.repaint();
		fieldLayoutManager.layoutContainer(codepane);
		codepane.requestFocusInWindow();
	}

	private AssembleDockingAction(String name, String owner) {
		super(name, owner);
		String group = "Disassembly";
		setPopupMenuData(new MenuData(new String[] { "Patch Instruction" }, group));
		setKeyBindingData(new KeyBindingData(KEYBIND_ASSEMBLE));
		setHelpLocation(new HelpLocation("AssemblerPlugin", "AssembleAction"));
	}

	/**
	 * Retrieve the location in the code viewer's {@link FieldPanel} for the field at the given
	 * address having the given header text
	 * 
	 * @param address the address
	 * @param fieldName the name of the field
	 * @return if found, the {@link FieldLocation}, otherwise {@code null}
	 */
	protected FieldLocation findFieldLocation(Address address, String fieldName) {
		Layout layout = listpane.getLayout(address);
		ListingModelAdapter adapter = (ListingModelAdapter) codepane.getLayoutModel();
		BigInteger index = adapter.getAddressIndexMap().getIndex(address);
		int count = layout.getNumFields();
		for (int i = 0; i < count; i++) {
			ListingField field = (ListingField) layout.getField(i);
			if (field.getFieldFactory().getFieldName().equals(fieldName)) {
				return new FieldLocation(index, i);
			}
		}
		return null;
	}

	static enum AssemblyRating {
		UNRATED("This processor has not been tested with the assembler." +
			" If you are really lucky, the assembler will work on this language." +
			" Please contact the Ghidra team if you'd like us to test, rate, and/or improve this language."),
		POOR("This processor received a rating of POOR during testing." +
			" Please contact the Ghidra team if you'd like to assemble for this language." +
			" Until then, we DO NOT recommend trying to assemble."),
		BRONZE("This processor received a rating of BRONZE during testing." +
			" Please contact the Ghidra team if you'd like to assemble for this language." +
			" A fair number of instruction may assemble, but we DO NOT recommend trying to assemble."),
		SILVER("This processor received a rating of SILVER during testing." +
			" Most instruction should work, but you will likely encounter a few errors." +
			" Please contact the Ghidra team if you'd like certain instruction improved."),
		GOLD("This processor received a rating of GOLD during testing." +
			" You should rarely encounter an error, but please let us know if you do."),
		PLATINUM("This processor received a rating of PLATINUM during testing.");

		final String message;

		private AssemblyRating(String message) {
			this.message = message;
		}
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof ListingActionContext)) {
			return;
		}
		prepareLayout(context);
		if (cv.isReadOnly()) {
			return;
		}
		ListingActionContext lac = (ListingActionContext) context;

		ProgramLocation cur = lac.getLocation();

		prog = cur.getProgram();
		addr = cur.getAddress();
		MemoryBlock block = prog.getMemory().getBlock(addr);
		if (block == null || !block.isInitialized()) {
			return;
		}
		lang = prog.getLanguage();

		AssemblyRating rating =
			AssemblyRating.valueOf(lang.getProperty(ASSEMBLY_RATING + ":" + lang.getLanguageID(),
				AssemblyRating.UNRATED.name()));
		if (AssemblyRating.PLATINUM != rating) {
			String message =
				lang.getProperty(ASSEMBLY_MESSAGE + ":" + lang.getLanguageID(), rating.message);
			if (!shownWarning.get(lang)) {
				Msg.showWarn(this, cv.getComponent(), "Assembler Rating",
					"<html><body><p style='width: 300px;'>" + message + "</p></body></html>");
				shownWarning.put(lang, true);
			}
		}

		cache.get(lang).get(null);
		assembler = Assemblers.getAssembler(prog);

		input.setProgramLocation(cur);
		FieldLocation locMnem = findFieldLocation(addr, "Mnemonic");
		if (null == locMnem) {
			Msg.showError(this, codepane, "Assemble",
				"The mnemonic field must be present to assemble");
			return;
		}
		FieldLocation locOpns = findFieldLocation(addr, "Operands");

		codepane.removeAll();
		if (null == locOpns) {
			// There is no operands field. Use the single-box variant
			codepane.add(input.getAssemblyField(), locMnem);
			input.setVisible(VisibilityMode.SINGLE_VISIBLE);
		}
		else {
			// Use the split-field variant
			codepane.add(input.getMnemonicField(), locMnem);
			codepane.add(input.getOperandsField(), locOpns);
			input.setVisible(VisibilityMode.DUAL_VISIBLE);
		}

		// Set the default text, only if it's currently an instruction
		CodeUnit cu = prog.getListing().getCodeUnitAt(addr);
		if (cu instanceof Instruction) {
			Instruction ins = (Instruction) cu;
			String instr = ins.toString();
			if (ins.isInDelaySlot()) {
				assert instr.startsWith("_");
				instr = instr.substring(1).trim();
			}
			input.setText(instr);
			input.setCaretPosition(instr.length());
			if (null == locOpns) {
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
			if (null == locOpns) {
				input.getAssemblyField().grabFocus();
			}
			else {
				input.getMnemonicField().grabFocus();
			}
		}
		fieldLayoutManager.layoutContainer(codepane);
		//JTextField opns = dual.getOperandsField();
		//opns.grabFocus();
		//opns.setCaretPosition(opns.getText().length());
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {

		// currently only works on a listing that has a CodeViewerProvider
		if (!(context instanceof ListingActionContext)) {
			return false;
		}

		ListingActionContext lac = (ListingActionContext) context;
		ComponentProvider cp = lac.getComponentProvider();
		if (!(cp instanceof CodeViewerProvider)) {
			return false;
		}

		CodeViewerProvider codeViewer = (CodeViewerProvider) cp;
		if (codeViewer.isReadOnly()) {
			return false;
		}

		Program program = lac.getProgram();
		if (program == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(lac.getAddress());
		if (block == null || !block.isInitialized()) {
			return false;
		}
		return true;
	}
}
