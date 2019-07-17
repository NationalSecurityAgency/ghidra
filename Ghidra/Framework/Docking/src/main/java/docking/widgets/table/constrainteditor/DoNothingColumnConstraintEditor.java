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

import java.awt.Component;

import javax.swing.JPanel;

import docking.widgets.table.constraint.ColumnConstraint;

/**
 * Editor for constraints that don't have a value that needs editing.  The "IsEmpty" constraint
 * is an example of a constraint that doesn't need an editor.
 *
 * @param <T> the column type.
 */
public class DoNothingColumnConstraintEditor<T> extends AbstractColumnConstraintEditor<T> {

	public DoNothingColumnConstraintEditor(ColumnConstraint<T> constraint) {
		super(constraint);
	}

	@Override
	public void reset() {
		// do nothing
	}

	@Override
	public String getErrorMessage() {
		return null;
	}

	@Override
	protected ColumnConstraint<T> getValueFromComponent() {
		return currentConstraint;
	}

	@Override
	protected Component buildInlineEditorComponent() {
		return new JPanel();
	}

	@Override
	protected void updateEditorComponent() {
		// do nothing
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		// do nothing
	}

	@Override
	protected boolean checkEditorValueValidity() {
		return true;
	}

}
