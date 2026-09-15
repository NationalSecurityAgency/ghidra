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

import java.awt.*;
import java.awt.event.*;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.JTextComponent;

import docking.widgets.autocomplete.AutocompletionListener;
import docking.widgets.autocomplete.TextComponentAutocompleter;
import docking.widgets.label.GDLabel;
import docking.widgets.textfield.TextFieldLinker;
import generic.theme.Gui;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.assembler.completion.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.util.NumericUtilities;

/**
 * A pair of text fields suitable for guided assembly
 * 
 * <p>
 * This object must be updated with program location information, so that it knows the applicable
 * language and address. It then provides two text boxes: one for the mnemonic, and one for the
 * operands. The two are linked so that the user can intuitively navigate between them as if they
 * were a single text box. The boxes are also attached to an autocompleter. It provides suggestions
 * based syntax errors returned by the assembler. When a valid instruction is present, it provides
 * the resulting instruction bytes.
 * 
 * <p>
 * To detect when the user has activated an instruction-bytes entry, add an
 * {@link AutocompletionListener} and check that the selection is an
 * {@link InstructionAssemblyCompletion}. Otherwise, the usual autocompletion behavior is applied
 * automatically.
 */
public class AssemblyDualTextField {
	private static final String FONT_ID = "font.plugin.assembly.dual.text.field";

	/**
	 * A listener which activates the autocompleter on ENTER (in addition to the default
	 * CTRL-SPACE).
	 * <p>
	 * Because the user must activate an entry to specify the desired assembly, we make ENTER pull
	 * up the list, hinting that the user must make a selection.
	 */
	protected class EnterKeyListener implements KeyListener {
		@Override
		public void keyTyped(KeyEvent e) {
			if (e.getKeyChar() != KeyEvent.VK_ESCAPE) {
				auto.setCompletionListVisible(true);
			}
		}

		@Override
		public void keyPressed(KeyEvent e) {
			if (e.isConsumed()) {
				return;
			}
			if (e.getKeyCode() == KeyEvent.VK_ENTER) {
				if (!auto.isCompletionListVisible()) {
					auto.startCompletion((JTextField) e.getComponent());
					e.consume();
				}
			}
		}

		@Override
		public void keyReleased(KeyEvent e) {
			// Blank
		}
	}

	class MyAutocompleter extends AssemblyAutocompleter {
		public MyAutocompleter() {
			super(model);
		}

		@Override
		protected String getPrefix(JTextComponent component) {
			if (component == assembly) {
				return component.getText().substring(0, component.getCaretPosition());
			}
			return linker.getTextBeforeCursor((JTextField) component);
		}

		@Override
		protected Point getCompletionWindowPosition() {
			if (assembly.isVisible()) {
				Point p = new Point(0, assembly.getHeight());
				SwingUtilities.convertPointToScreen(p, assembly);
				return p;
			}
			Point p = new Point(0, 0);
			SwingUtilities.convertPointToScreen(p, mnemonic);
			Point q = new Point(0, linker.getFocusedField().getHeight());
			SwingUtilities.convertPointToScreen(q, linker.getFocusedField());
			p.y = q.y;
			return p;
		}

		@Override
		protected Dimension getDefaultCompletionWindowDimension() {
			int width = 0;
			if (assembly.isVisible()) {
				width = assembly.getWidth();
			}
			else {
				Point p = new Point(0, 0);
				SwingUtilities.convertPointToScreen(p, mnemonic);
				Point q = new Point(operands.getWidth(), 0);
				SwingUtilities.convertPointToScreen(q, operands);
				width = q.x - p.x;
			}
			return new Dimension(width, -1);
		}
	}

	protected class AssemblyDualTextAutocompletionModel extends AssemblyAutocompletionModel {
		@Override
		public Collection<AssemblyCompletion> computeCompletions(String text) {
			// Don't use text passed in. Get full text of dual fields.
			return super.computeCompletions(getText());
		}
	}

	protected final TextFieldLinker linker = new TextFieldLinker();
	protected final JTextField mnemonic = new JTextField();
	protected final JTextField operands = new JTextField();
	protected final JTextField assembly = new JTextField();

	protected final AssemblyAutocompletionModel model = newAutocompletionModel();
	protected final AssemblyAutocompleter auto = new MyAutocompleter();
	protected final EnterKeyListener enterListener = new EnterKeyListener();

	/**
	 * Construct the assembly text fields
	 */
	public AssemblyDualTextField() {

		// Configure the linked fields
		linker.linkField(mnemonic, "\\s+", " ");
		auto.attachTo(mnemonic);
		mnemonic.addKeyListener(enterListener);
		configureField(mnemonic);
		mnemonic.setName("AssemblerMnemonic");

		linker.linkLastField(operands);
		auto.attachTo(operands);
		operands.addKeyListener(enterListener);
		configureField(operands);
		operands.setName("AssemblerOperands");
		operands.setFocusTraversalKeysEnabled(false);

		// Configure the unlinked variant
		auto.attachTo(assembly);
		configureField(assembly);
		assembly.addKeyListener(enterListener);
		assembly.setName("AssemblerSingleField");
		assembly.setFocusTraversalKeysEnabled(false);
	}

	protected AssemblyDualTextAutocompletionModel newAutocompletionModel() {
		return new AssemblyDualTextAutocompletionModel();
	}

	void dispose() {
		auto.dispose();
	}

	/**
	 * Set the assembler to use
	 * 
	 * @param assembler the assembler
	 */
	public void setAssembler(Assembler assembler) {
		model.setAssembler(assembler);
	}

	/**
	 * Set the address of the assembly instruction
	 * <p>
	 * Note this will reset the existing instruction to null to prevent its accidental re-use. See
	 * {@link #setExisting(Instruction)}.
	 * 
	 * @param address the address
	 */
	public void setAddress(Address address) {
		model.setAddress(address);
	}

	/**
	 * Set the "existing" instruction used for ordering proposed instructions by "most similar"
	 * 
	 * @param existing the existing instruction
	 */
	public void setExisting(Instruction existing) {
		model.setExisting(existing);
	}

	/**
	 * For dual mode: Get the text field containing the mnemonic portion of the assembly
	 * 
	 * @return the text field
	 */
	public JTextField getMnemonicField() {
		return mnemonic;
	}

	/**
	 * For dual mode: Get the text field containing the operands portion of the assembly
	 * 
	 * @return the text field
	 */
	public JTextField getOperandsField() {
		return operands;
	}

	/**
	 * Get the button that toggles bit exhaustion
	 * 
	 * @return the button
	 */
	public JButton getExhaustButton() {
		return auto.getExhaustButton();
	}

	/**
	 * For single mode: Get the text field containing the full assembly text
	 * 
	 * @return the text field
	 */
	public JTextField getAssemblyField() {
		return assembly;
	}

	/**
	 * Get a reference to the autocompleter
	 * 
	 * <p>
	 * This is useful for adding the custom listener needed to detect activation of assembled
	 * instruction entries.
	 * 
	 * @return the autocompleter
	 */
	public TextComponentAutocompleter<AssemblyCompletion> getAutocompleter() {
		return auto;
	}

	/**
	 * Clear all text boxes
	 */
	public void clear() {
		linker.clear();
		assembly.setText("");
	}

	/**
	 * An enum type to specify which variant of the assembly input is shown.
	 */
	public enum VisibilityMode {
		/**
		 * Hide both variants. Nothing is shown.
		 */
		INVISIBLE,
		/**
		 * Show the dual-box linked variant, suitable when the current instruction has operands.
		 */
		DUAL_VISIBLE,
		/**
		 * Show the single-box unlinked variant, suitable when the current instruction has no
		 * operands.
		 */
		SINGLE_VISIBLE;
	}

	/**
	 * Set the visibility of the text box(es)
	 * 
	 * @param visibility the {@link VisibilityMode} to set.
	 */
	public void setVisible(VisibilityMode visibility) {
		switch (visibility) {
			case INVISIBLE:
				linker.setVisible(false);
				assembly.setVisible(false);
				break;
			case DUAL_VISIBLE:
				linker.setVisible(true);
				assembly.setVisible(false);
				break;
			case SINGLE_VISIBLE:
				linker.setVisible(false);
				assembly.setVisible(true);
				break;
		}
	}

	/**
	 * Get the visibility of the text box(es)
	 * 
	 * <p>
	 * <b>NOTE:</b> This method assumes nothing else changes the visibility of the text boxes. If
	 * anything else does, then it should be sure to maintain a configuration consistent with one of
	 * the {@link VisibilityMode}s.
	 * 
	 * @return the current mode
	 */
	public VisibilityMode getVisible() {
		if (linker.isVisible()) {
			if (assembly.isVisible()) {
				throw new AssertionError();
			}
			return VisibilityMode.DUAL_VISIBLE;
		}

		if (assembly.isVisible()) {
			return VisibilityMode.SINGLE_VISIBLE;
		}
		return VisibilityMode.INVISIBLE;
	}

	/**
	 * Set the font for all text fields
	 * 
	 * @param font the new font
	 */
	public void setFont(Font font) {
		linker.setFont(font);
		assembly.setFont(font);
	}

	/**
	 * Add a focus listener to the box(es)
	 * 
	 * <p>
	 * <b>NOTE:</b> The listener will not fire when focus passes among the linked boxes of the dual
	 * variant.
	 * 
	 * @param listener the listener
	 */
	public void addFocusListener(FocusListener listener) {
		linker.addFocusListener(listener);
		assembly.addFocusListener(listener);
	}

	/**
	 * Add a key listener to the box(es)
	 * 
	 * @param listener the listener
	 */
	public void addKeyListener(KeyListener listener) {
		mnemonic.addKeyListener(listener);
		operands.addKeyListener(listener);
		assembly.addKeyListener(listener);
	}

	/**
	 * Get the full assembly text
	 * 
	 * @return the text
	 */
	public String getText() {
		if (assembly.isVisible()) {
			return assembly.getText();
		}
		return linker.getText();
	}

	/**
	 * Set the text of the visible field(s)
	 * 
	 * @param text the text
	 */
	public void setText(String text) {
		if (assembly.isVisible()) {
			assembly.setText(text);
		}
		else {
			linker.setText(text);
		}
	}

	/**
	 * Set the caret position of the visible field(s)
	 * 
	 * @param pos the position
	 */
	public void setCaretPosition(int pos) {
		try {
			if (assembly.isVisible()) {
				assembly.setCaretPosition(pos);
			}
			else {
				linker.setCaretPosition(pos);
			}
		}
		catch (BadLocationException e) {
			assert false;
		}
	}

	/**
	 * Sets the style of the text fields
	 * 
	 * <p>
	 * This is an extension point.
	 * 
	 * @param field the field to configure
	 */
	protected void configureField(JTextField field) {
		Gui.registerFont(field, FONT_ID);
	}

	/**
	 * A demonstration of the assembly GUI outside of Ghidra
	 */
	public class AssemblyDualTextFieldDemo implements GhidraLaunchable {
		public final LanguageID DEMO_LANG_ID = new LanguageID("x86:LE:64:default");
		public final String ADDR_FORMAT = "@%08x:";
		Address curAddr;

		@Override
		public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
			Application.initializeApplication(layout, new ApplicationConfiguration());
			JDialog dialog = new JDialog((Window) null, "Assembly Autocompleter Demo");

			dialog.setLayout(new BorderLayout());

			Box hbox = Box.createHorizontalBox();
			dialog.add(hbox, BorderLayout.NORTH);

			JLabel addrlabel = new GDLabel(String.format(ADDR_FORMAT, curAddr));
			hbox.add(addrlabel);

			AssemblyDualTextField input = new AssemblyDualTextField();

			SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
			SleighLanguage lang = (SleighLanguage) provider.getLanguage(DEMO_LANG_ID);
			curAddr = lang.getDefaultSpace().getAddress(0);

			input.setAssembler(Assemblers.getAssembler(lang));
			input.setAddress(curAddr);

			hbox.add(input.getAssemblyField());
			hbox.add(input.getMnemonicField());
			hbox.add(Box.createHorizontalStrut(10));
			hbox.add(input.getOperandsField());

			JTextArea asm = new JTextArea();
			asm.setEditable(false);
			asm.setLineWrap(true);
			asm.setWrapStyleWord(false);
			dialog.add(asm, BorderLayout.CENTER);

			input.getAutocompleter().addAutocompletionListener(e -> {
				if (e.getSelection() instanceof InstructionAssemblyCompletion) {
					InstructionAssemblyCompletion ins =
						(InstructionAssemblyCompletion) e.getSelection();
					String data = NumericUtilities.convertBytesToString(ins.getData());
					asm.setText(asm.getText() + data);
					input.clear();
					curAddr = curAddr.addWrap(ins.getData().length);
					input.setAddress(curAddr);
					addrlabel.setText(String.format(ADDR_FORMAT, curAddr));
				}
			});

			AtomicReference<VisibilityMode> vis =
				new AtomicReference<>(VisibilityMode.DUAL_VISIBLE);
			input.setVisible(vis.get());
			KeyListener l = new KeyListener() {
				@Override
				public void keyTyped(KeyEvent e) {
					// NOTHING
				}

				@Override
				public void keyPressed(KeyEvent e) {
					if (e.isAltDown() && e.isShiftDown() && e.getKeyChar() == KeyEvent.VK_D) {
						if (vis.get() == VisibilityMode.DUAL_VISIBLE) {
							vis.set(VisibilityMode.SINGLE_VISIBLE);
						}
						else {
							vis.set(VisibilityMode.DUAL_VISIBLE);
						}
						input.setVisible(vis.get());
						dialog.validate();
					}
				}

				@Override
				public void keyReleased(KeyEvent e) {
					// NOTHING
				}
			};
			input.addKeyListener(l);

			asm.setVisible(true);

			dialog.setBounds(2560, 500, 400, 200);
			dialog.setModal(true);
			dialog.setVisible(true);
		}
	}
}
