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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.*;

import docking.DialogComponentProvider;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.Gui;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.SleighUtils.SleighParseError;
import ghidra.pcode.exec.SleighUtils.SleighParseErrorEntry;
import ghidra.util.*;

public abstract class AbstractDebuggerSleighInputDialog extends DialogComponentProvider {
	protected static final Color COLOR_ERROR = Colors.ERROR;
	protected static final AttributeSet RED_UNDERLINE;

	static {
		MutableAttributeSet attributes = new SimpleAttributeSet();
		StyleConstants.setForeground(attributes, COLOR_ERROR);
		StyleConstants.setUnderline(attributes, true);
		RED_UNDERLINE = attributes;
	}

	protected final JPanel panel;
	protected final JLabel label;
	protected final StyledDocument docInput;
	protected final JTextPane textInput;
	private JScrollPane spInput;
	protected boolean isValid = false;

	static class SleighTextPane extends JTextPane {
		public SleighTextPane(StyledDocument document) {
			super(document);
			Gui.registerFont(this, "font.debugger.sleigh");
		}
	}

	protected AbstractDebuggerSleighInputDialog(String title, String prompt) {
		super(title, true, true, true, false);
		panel = new JPanel(new BorderLayout());
		panel.setBorder(new EmptyBorder(16, 16, 16, 16));
		label = new JLabel(prompt);
		label.getMaximumSize().width = 400;
		panel.add(label, BorderLayout.NORTH);

		docInput = new DefaultStyledDocument();
		textInput = new SleighTextPane(docInput);
		spInput = new JScrollPane(textInput);
		spInput.getMaximumSize().height = 300;
		panel.add(spInput);

		addWorkPanel(panel);

		addOKButton();
		addCancelButton();
	}

	public String prompt(PluginTool tool, String defaultInput) {
		setStatusText("");
		textInput.setText(defaultInput);
		validateAndMarkup();
		Swing.runLater(() -> repack());
		tool.showDialog(this);
		if (isValid) {
			return getInput();
		}
		return null;
	}

	public String getInput() {
		return textInput.getText();
	}

	protected abstract void validate();

	protected void clearAttributes() {
		docInput.setCharacterAttributes(0, docInput.getLength() + 1, SimpleAttributeSet.EMPTY,
			true);
	}

	protected void addErrorAttribute(int start, int stop) {
		int length = stop - start + 1;
		docInput.setCharacterAttributes(start, length, RED_UNDERLINE, true);
	}

	protected void validateAndMarkup() {
		isValid = false;
		clearAttributes();
		try {
			validate();
			isValid = true;
		}
		catch (SleighParseError e) {
			setStatusText("<html><pre>" + HTMLUtilities.escapeHTML(e.getMessage()) + "</pre>",
				MessageType.ERROR, false);
			Swing.runLater(() -> {
				if (spInput.getPreferredSize().height > spInput.getSize().height) {
					repack();
				}
			});
			for (SleighParseErrorEntry error : e.getErrors()) {
				addErrorAttribute(error.start(), error.stop());
			}
		}
	}

	@Override
	protected void okCallback() {
		validateAndMarkup();
		if (isValid) {
			close();
		}
	}

	@Override
	protected void cancelCallback() {
		isValid = false;
		close();
	}
}
