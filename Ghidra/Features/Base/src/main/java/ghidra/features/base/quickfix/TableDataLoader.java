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
package ghidra.features.base.quickfix;

import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Generates table data for a {@link ThreadedTableModel}. Subclasses
 * of ThreadedTableModel can call a TableLoader to supply data in the model's doLoad() method. Also
 * has methods for the client to get feedback on the success of the load.
 * <P>
 * The idea is that instead of having to subclass the table model to overload the doLoad() method,
 * a general table model is sufficient and be handed a TableDataLoader to provide data to the model.
 *
 * @param <T> The type of objects to load into a table model.
 */
public interface TableDataLoader<T> {

	/**
	 * Loads data into the given accumulator
	 * @param accumulator the the accumulator for storing table data
	 * @param monitor the {@link TaskMonitor}
	 * @throws CancelledException if the operation is cancelled
	 */
	public void loadData(Accumulator<T> accumulator, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Returns true if at least one item was added to the accumulator.
	 * @return true if at least one item was added to the accumulator
	 */
	public boolean didProduceData();

	/**
	 * Returns true if the load was terminated because the maximum number of items was
	 * reached.
	 * @return true if the load was terminated because the maximum number of items was
	 * reached.
	 */
	public boolean maxDataSizeReached();

}
