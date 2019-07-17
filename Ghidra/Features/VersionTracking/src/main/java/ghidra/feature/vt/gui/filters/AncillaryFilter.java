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
package ghidra.feature.vt.gui.filters;

import java.util.HashSet;
import java.util.Set;

public abstract class AncillaryFilter<T> extends Filter<T> {

	private HashSet<FilterChangedListener> listeners = new HashSet<FilterChangedListener>();

	public void addFilterChangedListener(FilterChangedListener listener) {
		listeners.add(listener);
	}

	public void removeFilterChangedListener(FilterChangedListener listener) {
		listeners.remove(listener);
	}

	@Override
	protected void fireStatusChanged(FilterEditingStatus status) {
		// We've overridden this event firing to notify our state listeners of changes 
		fireFilterStateChanged();
	}

	@SuppressWarnings("unchecked") // we know the type is correct
	public void fireFilterStateChanged() {
		FilterState state = getFilterState();
		Set<FilterChangedListener> set = (Set<FilterChangedListener>) listeners.clone();
		for (FilterChangedListener listener : set) {
			listener.filterStateChanged(state);
		}
	}

	public abstract FilterState getFilterState();

	public abstract void restoreFilterState(FilterState state);
}
