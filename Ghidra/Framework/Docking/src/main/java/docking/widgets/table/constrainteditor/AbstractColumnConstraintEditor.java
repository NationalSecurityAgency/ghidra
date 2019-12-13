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

import javax.swing.UIManager;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.table.constraint.ColumnConstraint;
import ghidra.util.HTMLUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * Base class for many constraint editors, providing implementation for much of the interface.
 *
 * @param <T> the column type
 */
public abstract class AbstractColumnConstraintEditor<T> implements ColumnConstraintEditor<T> {
	protected ColumnConstraint<T> currentConstraint;

	private WeakSet<ChangeListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();
	private Component inlineEditorComponent = null;
	private Component detailEditorComponent = null;

	private boolean validEditorValue = false;

	/** Color indicating a valid value is defined by the editor widget(s) */
	protected static final Color VALID_INPUT_COLOR = UIManager.getColor("TextField.background");
	/** Color indicating a invalid value is defined by the editor widget(s) */
	protected static final Color INVALID_INPUT_COLOR = new Color(255, 0, 51, 40);

	/**
	 * Constructor.
	 *
	 * @param constraint the constraint this class is an editor for
	 */
	protected AbstractColumnConstraintEditor(ColumnConstraint<T> constraint) {
		this.currentConstraint = constraint;
	}

	/**
	 * Get the constraints' new value from the editor component.
	 *
	 * This expects the UI to have been constructed.
	 *
	 * @see #getValue()
	 * @return
	 */
	protected abstract ColumnConstraint<T> getValueFromComponent();

	/**
	 * Delegate the construction of the inline editor component.
	 *
	 * @see #getInlineComponent()
	 * @return the editors inline component
	 */
	protected abstract Component buildInlineEditorComponent();

	/**
	 * Indicates to subclasses that the constraint has changed, and the user interface
	 * needs to be updated to reflect the new state.
	 */
	protected abstract void updateEditorComponent();

	/**
	 * Delegate the construction of the detail editor component.
	 * <p>
	 * Subclasses should override this method if they choose to provide a
	 * detailed constraint editor. This is an optional feature, and this implementation
	 * returns null to satisfy the <code>ColumnConstraintEditor</code> contract.
	 *
	 * @see #getDetailComponent()
	 * @return the editors detail component; null in this implementation
	 */
	protected Component buildDetailEditorComponent() {
		return null;
	}

	@Override
	public final ColumnConstraint<T> getValue() {
		if (hasEditorComponents() && hasValidValue()) {
			currentConstraint = getValueFromComponent();
		}
		return currentConstraint;
	}

	@Override
	public final void setValue(ColumnConstraint<T> value) {
		currentConstraint = value;
		if (hasEditorComponents()) {
			updateEditorComponent();
		}
	}

	@Override
	public void addChangeListener(ChangeListener l) {
		if (l != null) {
			listeners.add(l);
		}
	}

	@Override
	public void removeChangeListener(ChangeListener l) {
		listeners.remove(l);
	}

	/**
	 * Notification that the editors' value has changed.
	 */
	protected void valueChanged() {
		if (!hasEditorComponents()) {
			return;
		}
		validEditorValue = checkEditorValueValidity();
		updateInfoMessage(validEditorValue);
		notifyConstraintChanged();
	}

	protected abstract void updateInfoMessage(boolean isValid);

	/**
	 * Template method that subclasses must implement.  This class will call this method whenever
	 * the value changes so that the validity state is updated.
	 * <p>
	 * Only called when the editor component has been constructed and UI elements are defined.
	 * @return true if the UI defines a valid value, false otherwise
	 * @see ColumnConstraintEditor#hasValidValue()
	 */
	abstract protected boolean checkEditorValueValidity();

	@Override
	public final boolean hasValidValue() {
		// if the editor hasn't been built yet, assume its valid since the user couldn't have
		// entered bad data yet.
		if (!hasEditorComponents()) {
			return true;
		}
		return validEditorValue;
	}

	/**
	 * Notify all monitors that the configuration of the constraint has changed.
	 */
	protected void notifyConstraintChanged() {
		ChangeEvent changeEvent = new ChangeEvent(this);
		for (ChangeListener changeListener : listeners) {
			changeListener.stateChanged(changeEvent);
		}
	}

	@Override
	public final Component getInlineComponent() {
		if (!hasEditorComponents()) {
			inlineEditorComponent = buildInlineEditorComponent();
			detailEditorComponent = buildDetailEditorComponent();
			updateEditorComponent();
			validEditorValue = checkEditorValueValidity();
			updateInfoMessage(validEditorValue);
		}
		return inlineEditorComponent;
	}

	@Override
	public final Component getDetailComponent() {
		if (!hasEditorComponents()) {
			inlineEditorComponent = buildInlineEditorComponent();
			detailEditorComponent = buildDetailEditorComponent();
			updateEditorComponent();
			validEditorValue = checkEditorValueValidity();
		}
		return detailEditorComponent;
	}

	/**
	 * Determine if the graphical elements of the editor have been constructed.
	 *
	 * @return true if the inline or detail editors have been built, false otherwise
	 */
	protected final boolean hasEditorComponents() {
		return inlineEditorComponent != null || detailEditorComponent != null;
	}

	/**
	 * Uses HTML to format and color a string depending on if it is an error or not.
	 *
	 * @param message the message to format.
	 * @param error true if the message is an error; false otherwise
	 * @return an HTML string suitable for a JLabel.
	 */
	protected final static String formatStatus(String message, boolean error) {
		Color color = error ? Color.RED : Color.BLACK;
		String messageWithFont = HTMLUtilities.setFont(message, color, 12);
		String html = HTMLUtilities.wrapAsHTML(messageWithFont);
		return html;
	}
}
