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
package ghidra.app.plugin.core.assembler.completion;

import java.awt.BorderLayout;
import java.awt.Color;
import java.math.BigInteger;
import java.util.Map.Entry;
import java.util.Objects;

import javax.swing.*;

import docking.EmptyBorderToggleButton;
import docking.widgets.autocomplete.*;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.app.util.viewer.field.ListingColors;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;

/**
 * A customized autocompleter for assembly
 * 
 * <p>
 * This positions the list at the bottom left of the field(s), and considers the full text of the
 * linked text boxes when retrieving the prefix. It also delegates the item styling to the item
 * instances.
 */
public class AssemblyAutocompleter extends TextComponentAutocompleter<AssemblyCompletion>
		implements AutocompletionListener<AssemblyCompletion> {
	static final Color FG_PREFERENCE_MOST =
		new GColor("color.fg.plugin.assembler.completion.most");
	static final Color FG_PREFERENCE_MIDDLE =
		new GColor("color.fg.plugin.assembler.completion.middle");
	static final Color FG_PREFERENCE_LEAST =
		new GColor("color.fg.plugin.assembler.completion.least");

	protected boolean exhaustUndefined = false;
	private final AssemblyAutocompletionModel model;

	public AssemblyAutocompleter(AssemblyAutocompletionModel model) {
		super(model);
		this.model = model;
	}

	/*testing*/ public void fakeFocusGained(JTextField field) {
		listener.fakeFocusGained(field);
	}

	@Override
	protected String getCompletionDisplay(AssemblyCompletion sel) {
		return sel.getDisplay();
	}

	@Override
	protected Color getCompletionForeground(AssemblyCompletion sel, boolean isSelected,
			boolean cellHasFocus) {
		if (!isSelected) {
			return sel.getColor();
		}
		return null;
	}

	@Override
	protected String getCompletionText(AssemblyCompletion sel) {
		return sel.getText();
	}

	@Override
	protected boolean getCompletionCanDefault(AssemblyCompletion sel) {
		return sel.getCanDefault();
	}

	private static final String CMD_EXHAUST = "Exhaust undefined bits";
	private static final String CMD_ZERO = "Zero undefined bits";

	private JLabel hints;
	EmptyBorderToggleButton exhaustButton;

	protected void createControlButtons(Box controls) {
		Icon icon = new GIcon("icon.plugin.assembler.question");
		exhaustButton = new EmptyBorderToggleButton(icon);
		exhaustButton.setToolTipText("Exhaust unspecified bits, otherwise zero them");
		exhaustButton.addActionListener((e) -> {
			exhaustUndefined = CMD_EXHAUST.equals(e.getActionCommand());
			if (exhaustUndefined) {
				exhaustButton.setActionCommand(CMD_ZERO);
			}
			else {
				exhaustButton.setActionCommand(CMD_EXHAUST);
			}
			updateDisplayContents();
		});
		exhaustButton.setActionCommand(CMD_EXHAUST);
		controls.add(exhaustButton);
	}

	@Override
	protected void addContent(JPanel content) {
		JPanel panel = new JPanel(new BorderLayout());
		Box controls = Box.createHorizontalBox();
		createControlButtons(controls);
		panel.add(controls, BorderLayout.SOUTH);
		hints = new JLabel();
		panel.add(hints);
		content.add(panel, BorderLayout.SOUTH);

		addAutocompletionListener(this);

	}

	protected Program getProgram() {
		return model.getAssembler().getProgram();
	}

	@Override
	public void completionSelected(AutocompletionEvent<AssemblyCompletion> ev) {
		if (!(ev.getSelection() instanceof InstructionAssemblyCompletion ai)) {
			hints.setText("");
			return;
		}

		Program program = getProgram();
		if (program == null) {
			hints.setText("");
			return;
		}

		ProgramContext ctx = program.getProgramContext();
		Register ctxReg = ctx.getBaseContextRegister();
		StringBuilder sb = new StringBuilder("""
				<html><style>
				ul.addresses {
				  margin: 0;
				  padding: 0;
				}
				ul.addresses > li {
				  margin: 0;
				  padding: 0;
				  list-style-type: none;
				}
				ul.context {
				  font-family: monospaced;
				  margin: 0 0 0 20px;
				}
				span.addr {
				  font-family: monospaced;
				}
				</style><body width="300px"><ul class="addresses">
				""".formatted(ListingColors.REGISTER.toHexString()));
		boolean displayedAny = false;
		for (Entry<Address, RegisterValue> ent : ai.contextChanges.contextsOut.entrySet()) {
			RegisterValue defVal = ctx.getDefaultDisassemblyContext();
			RegisterValue newVal = defVal.combineValues(ent.getValue());
			RegisterValue curVal =
				defVal.combineValues(ctx.getRegisterValue(ctxReg, ent.getKey()));

			boolean displayedAddress = false;
			for (Register sub : ctxReg.getChildRegisters()) {
				BigInteger newSubVal =
					newVal.getRegisterValue(sub).getUnsignedValueIgnoreMask();
				BigInteger curSubVal =
					curVal.getRegisterValue(sub).getUnsignedValueIgnoreMask();
				if (Objects.equals(curSubVal, newSubVal)) {
					continue;
				}
				if (!displayedAddress) {
					sb.append("""
							<li>At <span class="addr">%s</span></li>
							<ul class="context">
							""".formatted(ent.getKey()));
					displayedAddress = true;
				}
				sb.append("""
						<li>%s := 0x%s</li>
						""".formatted(sub.getName(), newSubVal.toString(16)));
				displayedAny = true;
			}
			if (displayedAddress) {
				sb.append("""
						</ul>
						""");
			}
		}
		if (!displayedAny) {
			hints.setText("");
		}
		sb.append("""
				</ul></body></html>
				""");
		hints.setText(sb.toString());
	}

	@Override
	public void completionActivated(AutocompletionEvent<AssemblyCompletion> e) {
	}

	public EmptyBorderToggleButton getExhaustButton() {
		return exhaustButton;
	}
}
