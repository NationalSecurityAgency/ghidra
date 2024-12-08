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
package docking.widgets.values;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.label.GHtmlLabel;
import ghidra.util.HTMLUtilities;
import ghidra.util.MessageType;
import ghidra.util.layout.PairLayout;

/**
 * Dialog for displaying and editing values defined in a {@link GValuesMap}. The dialog consists
 * of an option message, followed by a list of name / value pairs. The name / value pairs will
 * be display in the order they were defined in the ValuesMap.
 */
public class ValuesMapDialog extends DialogComponentProvider {

	private static final int MAX_MESSAGE_LINE_WIDTH = 60;
	private JPanel valuesPanel;
	private GValuesMap valuesMap;
	private boolean cancelled = false;
	private String message;

	/**
	 * Creates the dialog with the given title and optional message. The message will be display
	 * at the top of the dialog before the list of name / value pairs. This form of the dialog
	 * requires that the {@link #addValue(AbstractValue)} method be called to populate the
	 * ValuesMap.
	 * @param title the title for the dialog
	 * @param message the optional message to display before the list of name value pairs
	 */
	public ValuesMapDialog(String title, String message) {
		this(title, message, new GValuesMap());
	}

	/**
	 * Creates the dialog with the given title and optional message. The message will be display
	 * at the top of the dialog before the list of name / value pairs. The values are provided
	 * at construction time.
	 * @param title the title for the dialog
	 * @param message the optional message to display before the list of name value pairs
	 * @param valuesMap the ValuesMap whose values are to be displayed.
	 */
	public ValuesMapDialog(String title, String message, GValuesMap valuesMap) {
		super(title);
		this.message = message;
		this.valuesMap = valuesMap;

		valuesPanel = buildValuesPanel();

		addWorkPanel(buildWorkPanel());

		for (AbstractValue<?> value : valuesMap.getValues()) {
			buildComponentsForValue(value);
		}
		setRememberSize(false);

		addOKButton();
		addCancelButton();
	}

	/**
	 * Adds a new value to the ValuesMap being edited by this dialog.
	 * @param value the new AbstractValue to be added
	 * @return the value that was added
	 */
	public AbstractValue<?> addValue(AbstractValue<?> value) {
		valuesMap.addValue(value);
		buildComponentsForValue(value);
		return value;
	}

	/**
	 * Sets the {@link ValuesMapValidator} on the ValuesMap being edited. This is usually set on the
	 * ValuesMap before the dialog is constructed. This method is for uses where it wasn't 
	 * constructed with a ValueMap, but values were added directly to the dialog after dialog
	 * construction.
	 * @param validator the ValuesMapValidator
	 */
	public void setValidator(ValuesMapValidator validator) {
		valuesMap.setValidator(validator);
	}

	/**
	 * Returns the ValuesMap being edited.
	 * @return the ValuesMap being edited.
	 */
	public GValuesMap getValues() {
		if (cancelled) {
			return null;
		}
		return valuesMap;
	}

	/**
	 * Returns true if the dialog was cancelled.
	 * @return true if the dialog was cancelled.
	 */
	public boolean isCancelled() {
		return cancelled;
	}

	@Override
	protected void okCallback() {
		try {
			valuesMap.updateFromComponents();
		}
		catch (ValuesMapParseException e) {
			setStatusText(e.getMessage(), MessageType.ERROR);
			return;
		}
		if (valuesMap.isValid(this)) {
			close();
		}
	}

	@Override
	protected void cancelCallback() {
		valuesMap.reset();
		cancelled = true;
		super.cancelCallback();
	}

	private JPanel buildValuesPanel() {
		JPanel panel = new JPanel(new PairLayout(4, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		return panel;
	}

	private JComponent buildWorkPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		if (message != null) {
			String literalHTML = HTMLUtilities.toLiteralHTML(message, MAX_MESSAGE_LINE_WIDTH);
			GHtmlLabel label = new GHtmlLabel(literalHTML);

			label.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
			panel.add(label, BorderLayout.NORTH);
		}

		JScrollPane scroll = new JScrollPane(valuesPanel);
		scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		panel.add(scroll, BorderLayout.CENTER);
		return panel;
	}

	private void buildComponentsForValue(AbstractValue<?> value) {
		valuesPanel.add(new JLabel(value.getName() + ":", SwingConstants.RIGHT));
		valuesPanel.add(value.getComponent());
		value.updateComponentFromValue();
	}

}
