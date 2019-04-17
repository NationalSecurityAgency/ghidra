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
package ghidra.app.util.query;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.TableSortingContext;

public abstract class AlignedObjectBasedPreviewTableModel<ROW_TYPE> extends
		AddressBasedTableModel<ROW_TYPE> {

	protected int alignment = 1;
	protected int[] filteredIndices = new int[0];
	private WeakSet<AddressAlignmentListener> alignmentListeners;

	protected AlignedObjectBasedPreviewTableModel(String modelName, ServiceProvider provider,
			Program prog, TaskMonitor monitor) {
		this(modelName, provider, prog, monitor, false);
	}

	protected AlignedObjectBasedPreviewTableModel(String modelName, ServiceProvider provider,
			Program prog, TaskMonitor monitor, boolean loadIncrementally) {
		super(modelName, provider, prog, monitor, loadIncrementally);
		alignmentListeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();
	}

	public void addAlignmentListener(AddressAlignmentListener alignmentListener) {
		alignmentListeners.add(alignmentListener);
	}

	public void removeAlignmentListener(AddressAlignmentListener alignmentListener) {
		alignmentListeners.remove(alignmentListener);
	}

	public int getAlignment() {
		return alignment;
	}

	public void setAlignment(int alignment) {
		if (alignment <= 0) {
			throw new IllegalArgumentException("Alignment cannot be less than 1.");
		}
		this.alignment = alignment;
		reFilter();
		for (AddressAlignmentListener alignListener : alignmentListeners) {
			alignListener.alignmentChanged();
		}
	}

	@Override
	public List<ROW_TYPE> doFilter(List<ROW_TYPE> data,
			TableSortingContext<ROW_TYPE> sortingContext, TaskMonitor monitor)
			throws CancelledException {

		// our default filtering; based upon alignment
		List<ROW_TYPE> filteredList = new ArrayList<ROW_TYPE>();
		for (int index = 0; index < data.size(); index++) {
			Address address = getAlignmentAddress(data, index);
			if (address.getOffset() % alignment == 0) {
				filteredList.add(data.get(index));
			}
		}

		// now apply the default, text-based filtering
		return super.doFilter(filteredList, sortingContext, monitor);
	}

	@Override
	protected void doLoad(Accumulator<ROW_TYPE> accumulator, TaskMonitor monitor)
			throws CancelledException {
		initializeUnalignedList(accumulator, monitor);
	}

	protected abstract void initializeUnalignedList(Accumulator<ROW_TYPE> accumulator,
			TaskMonitor monitor) throws CancelledException;

	protected abstract Address getAlignmentAddress(List<ROW_TYPE> localList, int index);
}
