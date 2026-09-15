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
package docking.widgets.trable;

import java.util.ArrayList;
import java.util.List;

/**
 * Abstract base class for GTrable models. Adds support for listeners.
 *
 * @param <T> the row data object type
 */
public abstract class AbstractGTrableRowModel<T> implements GTrableRowModel<T> {
	private List<GTrableModeRowlListener> listeners = new ArrayList<>();

	@Override
	public void addListener(GTrableModeRowlListener l) {
		listeners.add(l);
	}

	@Override
	public void removeListener(GTrableModeRowlListener l) {
		listeners.remove(l);
	}

	protected void fireModelChanged() {
		for (GTrableModeRowlListener listener : listeners) {
			listener.trableChanged();
		}
	}

}
