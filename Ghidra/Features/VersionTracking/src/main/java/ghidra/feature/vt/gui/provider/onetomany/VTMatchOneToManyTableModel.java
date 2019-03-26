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
package ghidra.feature.vt.gui.provider.onetomany;

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.AbstractVTMatchTableModel;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.Comparator;

public abstract class VTMatchOneToManyTableModel extends AbstractVTMatchTableModel {

	protected Address address = null;

	public VTMatchOneToManyTableModel(String title, VTController vtController) {
		super(title, vtController);
	}

	@Override
	protected Comparator<VTMatch> createSortComparator(int columnIndex) {
		return super.createSortComparator(columnIndex);
	}

	@Override
	protected abstract void doLoad(Accumulator<VTMatch> accumulator, TaskMonitor monitor)
			throws CancelledException;

	public void setAddress(Address matchAddress) {
		address = matchAddress;
		reload();
	}
}
