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

/**
 * Defines the contract for building user-interface elements for manipulating
 * constraint configuration.
 *
 * @param <T> the column type
 */
public interface ColumnConstraintEditor<T> {

	/**
	 * The <i>inline</i> component resides in the configuration interface on the same
	 * visual line as the column and constraint selection widgets. It is intended to be
	 * a relatively small and simple interface for configuring the constraints' values.
	 * @return the inline editor component
	 */
	public Component getInlineComponent();

	/**
	 * The <i>detail</i> component resides in the configuration interface below
	 * the column and constraint selection widgets, and is afforded greater space.
	 * It is intended to be a more feature-rich editor that provides greater
	 * insight or control of the constraints value definition.
	 *
	 * @return the detail editor component
	 */
	public Component getDetailComponent();

	/**
	 * Get the current value from the editor, in the form of a constraint.
	 * @return the editors' current value
	 */
	public ColumnConstraint<T> getValue();

	/**
	 * Set the current value within the editor
	 * @param value the new value to set
	 */
	public void setValue(ColumnConstraint<T> value);

	/**
	 * Reset the editor to a known-good state.
	 */
	public void reset();

	/**
	 * Determine if the editor contains a valid value; do the UI widgets and state
	 * match, is the state sensible for the constraint.
	 * @return true if the configuration is valid, false otherwise
	 */
	public boolean hasValidValue();

	/**
	 * If the editor contains and invalid value, this message should indicate
	 * why the value is invalid. Only called if <code>hasValidValue()</code> returns false.
	 * @return an error message, or an empty string if no error
	 */
	public String getErrorMessage();

	/**
	 * Register a callback handler for responding to changes made within the editor
	 * @param constraintEditorChangeListener listener callback
	 */
	public void addChangeListener(ChangeListener constraintEditorChangeListener);

	/**
	 * Remove a callback handler that was responding changes made within the editor
	 * @param constraintEditorChangeListener listener callback
	 */
	public void removeChangeListener(ChangeListener constraintEditorChangeListener);
}
