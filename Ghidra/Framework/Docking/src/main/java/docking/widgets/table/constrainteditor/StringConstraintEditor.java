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
package docking.widgets.table.constrainteditor;

import java.awt.*;

import javax.swing.*;

import docking.widgets.label.GDHtmlLabel;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.StringColumnConstraint;

/**
 * A constraint editor for String-type values.
 */
public class StringConstraintEditor extends AbstractColumnConstraintEditor<String> {

	protected JTextField textField;
	private String errorMessage;
	private JLabel infoLabel;

	/**
	 * Constructor.
	 *
	 * @param constraint String-type constraint for which this component is an editor.
	 * @param errorMessage the message to display if the textField is blank.
	 */
	public StringConstraintEditor(StringColumnConstraint constraint, String errorMessage) {
		super(constraint);
		this.errorMessage = errorMessage;
	}

	@Override
	protected Component buildInlineEditorComponent() {

		JPanel panel = new JPanel(new BorderLayout());
		textField = new JTextField();
		textField.getDocument().addUndoableEditListener(e -> valueChanged());

		panel.add(textField, BorderLayout.CENTER);

		infoLabel = new GDHtmlLabel("abc");  // temporary text in the label so that it sizes properly
		infoLabel.setForeground(Color.RED);
		infoLabel.setHorizontalAlignment(SwingConstants.CENTER);
		panel.add(infoLabel, BorderLayout.SOUTH);
		return panel;
	}

	@Override
	protected ColumnConstraint<String> getValueFromComponent() {
		String newPatternString = textField.getText().trim();
		return getConstraint().copy(newPatternString);
	}

	@Override
	public void reset() {
		setValue(getConstraint().copy(""));
	}

	@Override
	protected boolean checkEditorValueValidity() {
		return getConstraint().isValidPatternString(textField.getText().trim());
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		// uses &nbsp to presever the labels height.
		String status = formatStatus(isValid ? "&nbsp;" : errorMessage, true);
		infoLabel.setText(status);
	}

	@Override
	public String getErrorMessage() {
		if (hasValidValue()) {
			return "";
		}
		return "Please enter a pattern to match (You may use * and ? globbing characters)";
	}

	@Override
	protected void updateEditorComponent() {
		if (hasEditorComponents()) {
			textField.setText(getConstraint().getPatternString());
			textField.setCaretPosition(0);
		}
	}

	private StringColumnConstraint getConstraint() {
		return (StringColumnConstraint) currentConstraint;
	}
}
