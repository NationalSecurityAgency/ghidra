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
package docking.widgets.table.constraint.dialog;

import java.awt.Component;

import javax.swing.event.ChangeListener;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.ColumnData;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;
import docking.widgets.table.constrainteditor.DummyConstraintEditor;
import ghidra.util.Msg;

/**
 * This class represents an "or'able" condition in the DialogFilterConditionSet
 *
 * @param <T> the column type.
 */
public class DialogFilterCondition<T> {
	private String constraintName;
	private ColumnConstraintEditor<T> editor;
	private DialogFilterConditionSet<T> parent;
	private ChangeListener changeListener = e -> editorChanged();

	/**
	 * Constructor
	 *
	 * @param parentCondition the parent condition that created this condition.
	 */
	public DialogFilterCondition(DialogFilterConditionSet<T> parentCondition) {
		this(parentCondition, null);
	}

	/**
	 * Constructor when building from an existing ColumnTableFilter
	 *
	 * @param parent the parent condition that created this condition.
	 * @param constraint the constraint from an existing ColumnTableFilter.
	 */
	public DialogFilterCondition(DialogFilterConditionSet<T> parent,
			ColumnConstraint<T> constraint) {
		this.parent = parent;
		if (constraint == null) {
			constraint = parent.getColumnFilterData().getFirstConstraint();
		}
		constraintName = constraint.getName();
		editor = createEditor(constraint);
	}

	/**
	 * Returns a list of valid constraints for the column
	 *
	 * <P>Used by the dialog to populate the constraint comboBox
	 *
	 * @return a list of valid constraints for the column.
	 */
	public ColumnConstraint<?>[] getColumnConstraints() {
		return parent.getColumnFilterData().getConstraints();
	}

	/**
	 * Returns the name of the current constraint for this OrFilterCondition.
	 *
	 * @return  the name of the current constraint for this OrFilterCondition.
	 */
	public String getSelectedConstraintName() {
		return constraintName;
	}

	/**
	 * Returns the current Constraint for this OrFilterCondition.
	 *
	 * @return the current Constraint for this OrFilterCondition.
	 */
	public ColumnConstraint<T> getSelectedConstraint() {
		return parent.getColumnFilterData().getConstraint(constraintName);
	}

	/**
	 * Change the constraint to the constraint with the given name.
	 *
	 * @param constraintName the name of the constraint to change to.
	 */
	public void setSelectedConstraint(String constraintName) {
		ColumnFilterData<T> columnData = parent.getColumnFilterData();
		setConstraint(columnData.getConstraint(constraintName));
	}

	/**
	 * Return the constraint from the editor.
	 *
	 * @return the constraint from the editor.
	 */
	public ColumnConstraint<T> getConstraint() {
		return editor.getValue();
	}

	/**
	 * Returns true if the editor has a valid value.
	 *
	 * @return  true if the editor has a valid value.
	 */
	public boolean hasValidFilterValue() {
		return editor.hasValidValue();
	}

	/**
	 * Returns an editor component for use by the user to change the constraint value. This is the
	 * component that the dialog's filter panel will display inline with the constraint name.
	 *
	 * @return  an editor component for use by the user to change the constraint value.
	 */
	public Component getInlineEditorComponent() {
		return editor.getInlineComponent();
	}

	/**
	 * For future expansion, a larger component may be allowed that will be displayed on an entire
	 * line below the constraint name.
	 *
	 * @return  an editor component for use by the user to change the constraint value.
	 */
	public Component getDetailEditorComponent() {
		return editor.getDetailComponent();
	}

	/**
	 * Deletes this OrFilterCondition from its parent.  If it is the last one in the parent, the
	 * parent will then delete itself from its parent and so on.
	 */
	public void delete() {
		parent.delete(this);
	}

	/**
	 * Sets the constraint value from a string.  Used for testing.
	 *
	 * @param valueString the constraint value as a string that will be parsed.
	 * @param dataSource the table's DataSource object.
	 */
	public void setValue(String valueString, Object dataSource) {
		ColumnConstraint<T> constraint = editor.getValue();
		ColumnConstraint<T> value = constraint.parseConstraintValue(valueString, dataSource);
		setConstraint(value);
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tname: " + constraintName + ",\n" +
			"\tparent: " + parent + "\n" +
		"}";
		//@formatter:on
	}

	private ColumnConstraintEditor<T> buildDummyEditor() {
		Msg.error(this, "No editor for constraint '" + constraintName + "' -- building dummy");
		String message;
		if (StringUtils.isBlank(constraintName)) {
			message = "Constraint provides no editor";
		}
		else {
			message = "Constraint '" + constraintName + "' provides no editor";
		}

		return new DummyConstraintEditor<>(message);
	}

	private void setConstraint(ColumnConstraint<T> constraint) {
		String currentConstraintName = constraintName;
		this.constraintName = constraint.getName();

		if (editor != null) {
			updateColumnData(currentConstraintName, editor.getValue());
		}
		editor = createEditor(constraint);
		parent.conditionChanged(this);
	}

	private void updateColumnData(String currentConstraintName, ColumnConstraint<T> value) {
		ColumnFilterData<T> columnFilterData = parent.getColumnFilterData();
		columnFilterData.replace(value);
	}

	private ColumnConstraintEditor<T> createEditor(ColumnConstraint<T> constraint) {
		ColumnData<T> columnDataSource = parent.getColumnData();
		ColumnConstraintEditor<T> constraintEditor = constraint.getEditor(columnDataSource);
		if (constraintEditor == null) {
			constraintEditor = buildDummyEditor();
		}

		constraintEditor.addChangeListener(changeListener);
		return constraintEditor;
	}

	private void editorChanged() {
		parent.editorValueChanged(editor);
	}

}
