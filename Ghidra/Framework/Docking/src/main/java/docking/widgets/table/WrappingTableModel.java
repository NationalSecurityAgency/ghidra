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
package docking.widgets.table;

import javax.swing.event.TableModelEvent;
import javax.swing.table.TableModel;

/**
 * Signals that the implementing table model is wrapping another table model.
 */
public interface WrappingTableModel extends TableModel {

	/**
	 * Returns the wrapped model
	 * @return the model
	 */
	public TableModel getWrappedModel();

	/**
	 * Returns the unwrapped model's row for the given view row.
	 * @param viewRow the row in the GUI
	 * @return the row in the wrapped model's indexing
	 */
	public int getModelRow(int viewRow);

	/**
	 * Allows this wrapping model to get update notifications directly from the filtering framework
	 */
	public void wrappedModelChangedFromTableChangedEvent();

	/**
	 * This method allows us to call the delegate model with a translated event
	 * @param e the event
	 */
	public void fireTableChanged(TableModelEvent e);
}
