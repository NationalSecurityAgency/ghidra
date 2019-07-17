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
package ghidra.app.plugin.core.instructionsearch.model;

import java.util.Observable;
import java.util.Observer;

import javax.swing.table.DefaultTableModel;

import ghidra.app.plugin.core.instructionsearch.ui.InstructionTable;

/**
 * Defines the model that backs the {@link InstructionTable}.  The main reason for this so 
 * clients can register for changes on this model and receive notifications whenever
 * any underlying {@link InstructionTableDataObject} instances change.
 */
public class InstructionTableModel extends DefaultTableModel
		implements InstructionTableObserver {

	/**
	 * Constructor.  Initializes the table model with the {@link InstructionTableDataObject} array, and 
	 * registers the creator for any changes to those objects.
	 *
	 * @param tableContentsDO
	 * @param colNames
	 */
	public InstructionTableModel(InstructionTableDataObject[][] tableContentsDO, Object[] colNames) {
		super(tableContentsDO, colNames);

		// Register this model as a subscriber to each DO. This ensures that when a DO is updated (eg:
		// masked or unmasked), this model will be notified and can update its state.
		for (int i = 0; i < tableContentsDO.length; i++) {
			for (int j = 0; j < tableContentsDO[i].length; j++) {
				InstructionTableDataObject dataObj = tableContentsDO[i][j];
				dataObj.register(this);
			}
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public Class getColumnClass(int columnIndex) {
		return InstructionTableDataObject.class;
	}

	/**
	 * This is a method provided by the {@link Observer} interface and must be 
	 * implemented.  However, we will not be using it (see {@link InstructionTableObserver} 
	 * for details).
	 */
	@Override
	public void update(Observable o, Object arg) {
		// do nothing
	}

	/**
	 * Called whenever a {@link InstructionTableDataObject} has changed.
	 * 
	 * Note: This is our custom version of the update() method in the {@link Observer} 
	 * interface.
	 */
	@Override
	public void changed() {
		fireTableDataChanged();
	}
}
