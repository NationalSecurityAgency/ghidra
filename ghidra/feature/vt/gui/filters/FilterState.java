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

import java.util.HashMap;
import java.util.Map;

/**
 * A class that allows us to capture the current state of any {@link Filter}.  This state allows
 * us to tell if the filter has been modified.
 */
public class FilterState {

	private Map<Object, Object> properties = new HashMap<Object, Object>();
	private final Filter<?> filter;

	public FilterState(Filter<?> filter) {
		this.filter = filter;
	}

	public Filter<?> getFilter() {
		return filter;
	}

	public void put(Object key, Object value) {
		properties.put(key, value);
	}

	public Object get(Object key) {
		return properties.get(key);
	}

	public boolean isSame(FilterState state) {
		return equals(state);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " - '" + filter + "': " + properties;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((filter == null) ? 0 : filter.hashCode());
		result = prime * result + ((properties == null) ? 0 : properties.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		FilterState other = (FilterState) obj;
		if (filter == null) {
			if (other.filter != null) {
				return false;
			}
		}
		else if (!filter.equals(other.filter)) {
			return false;
		}
		if (properties == null) {
			if (other.properties != null) {
				return false;
			}
		}
		else if (!properties.equals(other.properties)) {
			return false;
		}
		return true;
	}

}
