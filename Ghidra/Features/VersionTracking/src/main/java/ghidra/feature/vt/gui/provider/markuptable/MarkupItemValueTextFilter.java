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
package ghidra.feature.vt.gui.provider.markuptable;

import docking.widgets.table.GTable;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.gui.filters.Filter;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.AbstractTextFilter;

class MarkupItemValueTextFilter extends AbstractTextFilter<VTMarkupItem> {

	public MarkupItemValueTextFilter(VTController controller, GTable table) {
		super(controller, table, "Value Filter");
	}

	@Override
	protected Filter<VTMarkupItem> createEmptyCopy() {
		return new MarkupItemValueTextFilter(controller, table);
	}

	@Override
	public boolean passesFilter(VTMarkupItem t) {
		return passesValueTextFilterImpl(t);
	}

	private boolean passesValueTextFilterImpl(VTMarkupItem adapter) {
		String filterText = getTextFieldText();
		if (filterText == null || filterText.trim().length() == 0) {
			return true; // no text for this filter
		}

		//
		// This filter is internally an OR filter, returning true if either source or 
		// destination value text matches the filter text
		//        
		Stringable sourceValue = adapter.getSourceValue();
		if (sourceValue != null) {
			String sourceValueText = sourceValue.getDisplayString();
			if (sourceValueText.toLowerCase().indexOf(filterText.toLowerCase()) != -1) {
				return true;
			}
		}

		Stringable destinationValue = adapter.getOriginalDestinationValue();
		if (destinationValue != null) {
			String destinationValueText = sourceValue.getDisplayString();
			if (destinationValueText.toLowerCase().indexOf(filterText.toLowerCase()) != -1) {
				return true;
			}
		}

		return false;
	}
}
