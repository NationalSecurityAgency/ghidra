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

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.JComboBox;
import javax.swing.JPanel;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.combobox.GComboBox;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.table.constraint.BooleanMatchColumnConstraint;
import docking.widgets.table.constraint.ColumnConstraint;

/**
 * A constraint editor for Boolean-type constraints, offering a choice of boolean values.
 */
public class BooleanConstraintEditor extends AbstractColumnConstraintEditor<Boolean> {
	private JComboBox<Boolean> comboBox;

	/**
	 * Constructor.
	 *
	 * @param constraint Boolean constraint for which this component is an editor.
	 */
	public BooleanConstraintEditor(BooleanMatchColumnConstraint constraint) {
		super(constraint);
	}

	@Override
	protected Component buildInlineEditorComponent() {

		JPanel panel = new JPanel(new BorderLayout());
		comboBox = new GComboBox<>(new Boolean[] { Boolean.TRUE, Boolean.FALSE });
		comboBox.setRenderer(GListCellRenderer.createDefaultCellTextRenderer(
			b -> StringUtils.capitalize(b.toString())));
		comboBox.addItemListener(e -> valueChanged());

		panel.add(comboBox, BorderLayout.CENTER);

		return panel;
	}

	@Override
	protected ColumnConstraint<Boolean> getValueFromComponent() {
		Boolean b = (Boolean) comboBox.getSelectedItem();
		return new BooleanMatchColumnConstraint(b);
	}

	@Override
	protected void updateEditorComponent() {
		if (hasEditorComponents()) {
			comboBox.setSelectedItem(getConstraint().getValue());
		}
	}

	@Override
	public void reset() {
		comboBox.setSelectedIndex(0);
	}

	@Override
	protected boolean checkEditorValueValidity() {
		return true;
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		// this editor does not have an info field
	}

	@Override
	public String getErrorMessage() {
		return "";
	}

	private BooleanMatchColumnConstraint getConstraint() {
		return (BooleanMatchColumnConstraint) currentConstraint;
	}

//==================================================================================================
// Test methods
//==================================================================================================

	JComboBox<Boolean> getComboBox() {
		return comboBox;
	}

}
