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

import javax.swing.event.ChangeListener;

import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.MappedColumnConstraint;

/**
 * A constraint editor that supports object type conversions, wrapping the editor for the
 * converted-to type. This is used to convert one column type to another that we already have
 * editors for. For example, suppose there is a Foo type where the column is returning Foo objects
 * but the rendering is just displaying Foo.getName().  In this case you would create a FooEditor
 * that wraps the various string editors. So even though the column uses Foo objects, the user
 * filters on just strings.
 *
 * @param <T> The column (mapped from) type.
 * @param <M> the mapped to type.
 */
public class MappedColumnConstraintEditor<T, M> implements ColumnConstraintEditor<T> {
	private ColumnConstraintEditor<M> delegateEditor;
	private MappedColumnConstraint<T, M> constraint;

	/**
	 * Constructor.
	 *
	 * @param constraint Type-converting constraint for which this component is an editor.
	 * @param delegateEditor Editor for the converted-to type.
	 */
	public MappedColumnConstraintEditor(MappedColumnConstraint<T, M> constraint,
			ColumnConstraintEditor<M> delegateEditor) {
		this.constraint = constraint;
		this.delegateEditor = delegateEditor;
	}

	@Override
	public Component getInlineComponent() {
		return delegateEditor.getInlineComponent();
	}

	@Override
	public Component getDetailComponent() {
		return delegateEditor.getDetailComponent();
	}

	@Override
	public ColumnConstraint<T> getValue() {
		ColumnConstraint<M> value = delegateEditor.getValue();
		return constraint.copy(value);
	}

	/**
	 * Sets the <code>T</code>-converted-to-<code>W</code> type in the delegate editor
	 * <p>
	 * {@inheritDoc}
	 *
	 * @param value the new value to set
	 */
	@Override
	public void setValue(ColumnConstraint<T> value) {
		// this is safe because the constraint and editor were created together and this
		// is guaranteed to be safe.
		@SuppressWarnings("unchecked")
		MappedColumnConstraint<T, M> newConstraint = (MappedColumnConstraint<T, M>) value;
		delegateEditor.setValue(newConstraint.getDelegate());
	}

	@Override
	public void reset() {
		delegateEditor.reset();
	}

	@Override
	public boolean hasValidValue() {
		return delegateEditor.hasValidValue();
	}

	@Override
	public String getErrorMessage() {
		return delegateEditor.getErrorMessage();
	}

	@Override
	public void addChangeListener(ChangeListener constraintEditorChangeListener) {
		delegateEditor.addChangeListener(constraintEditorChangeListener);
	}

	@Override
	public void removeChangeListener(ChangeListener constraintEditorChangeListener) {
		delegateEditor.addChangeListener(constraintEditorChangeListener);
	}
}
