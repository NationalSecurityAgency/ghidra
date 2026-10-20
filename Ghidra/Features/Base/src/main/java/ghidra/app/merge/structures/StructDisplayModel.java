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
package ghidra.app.merge.structures;

import java.util.Collections;
import java.util.List;

import javax.swing.AbstractListModel;
import javax.swing.ListModel;

import ghidra.app.merge.structures.CoordinatedStructureLine.CompareId;

/**
 * The {@link ListModel} model for one of the three structure displays.
 */
class StructDisplayModel extends AbstractListModel<ComparisonItem> {

	private CoordinatedStructureModel model;
	private CompareId compareId;
	private List<ComparisonItem> data;

	/**
	 * Constructor
	 * @param model the comparison model that has the coordinated lines for all three structures.
	 * @param compareId the id that says this is either the left, right, or merged list model.
	 * Used to get the appropriate list of comparison items from the
	 * {@link CoordinatedStructureModel}
	 */
	StructDisplayModel(CoordinatedStructureModel model, CompareId compareId) {
		this.model = model;
		this.compareId = compareId;
		model.addChangeListener(() -> modelChanged());
		data = model.getData(compareId);
	}

	private void modelChanged() {
		data = model.getData(compareId);
		fireContentsChanged(this, 0, model.getSize());
	}

	@Override
	public int getSize() {
		return data.size();
	}

	@Override
	public ComparisonItem getElementAt(int index) {
		return data.get(index);
	}

	/**
	 * Gets the list index of the corresponding item in this list model. Uses the line number info
	 * from the given item to find its internal item that has the same line number.
	 * @param item the item to use to find the corresponding item in this model
	 * @return the list index in this model for the item that has the same line number as the given
	 * item or -1 if not such item exits.
	 */
	int getIndex(ComparisonItem item) {
		if (item == null) {
			return -1;
		}
		return Collections.binarySearch(data, item);
	}

}
