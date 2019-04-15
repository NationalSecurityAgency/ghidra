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

import java.awt.Color;
import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.event.ChangeListener;

import docking.widgets.label.GDHtmlLabel;
import docking.widgets.table.constraint.ColumnConstraint;
import ghidra.util.HTMLUtilities;

/**
 * An editor that is always invalid.
 * <p>
 * Used internally to indicate a constraint does not provide an editor of its own.
 * @param <T>
 */
public final class DummyConstraintEditor<T> implements ColumnConstraintEditor<T> {

	private final String message;

	/**
	 * Constructor.
	 * 
	 * @param message to display
	 */
	public DummyConstraintEditor(String message) {
		this.message = message;
	}

	@Override
	public Component getInlineComponent() {
		JPanel panel = new JPanel();

		JLabel errorLabel = new GDHtmlLabel(
			"<html>" + HTMLUtilities.bold(HTMLUtilities.colorString(Color.RED, message)));

		panel.add(errorLabel);

		return panel;
	}

	@Override
	public Component getDetailComponent() {
		return null;
	}

	@Override
	public ColumnConstraint<T> getValue() {
		return null;
	}

	@Override
	public void setValue(ColumnConstraint<T> value) {
		// do nothing
	}

	@Override
	public void reset() {
		// do nothing
	}

	@Override
	public boolean hasValidValue() {
		return false;
	}

	@Override
	public String getErrorMessage() {
		return message;
	}

	@Override
	public void addChangeListener(ChangeListener constraintEditorChangeListener) {
		// do nothing
	}

	@Override
	public void removeChangeListener(ChangeListener constraintEditorChangeListener) {
		// do nothing
	}

}
