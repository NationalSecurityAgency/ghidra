/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.table;

import docking.widgets.table.*;
import docking.widgets.table.threaded.GThreadedTablePanel;
import docking.widgets.table.threaded.ThreadedTableModel;

public class GhidraThreadedTablePanel<T> extends GThreadedTablePanel<T> {

	public GhidraThreadedTablePanel(ThreadedTableModel<T, ?> model) {
		super(model);
	}

	public GhidraThreadedTablePanel(ThreadedTableModel<T, ?> model, int minUpdateDelay) {
		super(model, minUpdateDelay);
	}

	public GhidraThreadedTablePanel(ThreadedTableModel<T, ?> model, int minUpdateDelay,
			int maxUpdateDelay) {
		super(model, minUpdateDelay, maxUpdateDelay);
	}

	@Override
	protected GTable createTable(ThreadedTableModel<T, ?> model) {
		return new GhidraTable(model);
	}

	@Override
	public GhidraTable getTable() {
		return (GhidraTable) super.getTable();
	}
}
