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
package generic.theme;

import java.util.*;

import ghidra.util.Msg;

// TODO doc why 'cachedValue' is lazy loaded
public abstract class ThemeValue<T> implements Comparable<ThemeValue<T>> {
	private final String id;
	private final T value;
	private final String refId;
//	private T cachedValue;

	protected ThemeValue(String id, String refId, T value) {
		this.id = fromExternalId(id);
		this.refId = (refId == null) ? null : fromExternalId(refId);
		this.value = value;
		if (value instanceof GColor) {
			System.out.println("Whoa");
		}
	}

	protected abstract String getIdPrefix();

	public String getId() {
		return id;
	}

	public String getReferenceId() {
		return refId;
	}

	public T getRawValue() {
		return value;
	}

	public T get(GThemeValueMap preferredValues) {
//		if (cachedValue == null) {
		return doGetValue(preferredValues);
//		}
//		return cachedValue;
	}

	private T doGetValue(GThemeValueMap values) {
		ThemeValue<T> result = this;
		Set<String> visitedKeys = new HashSet<>();
		visitedKeys.add(id);	// seed with my id, we don't want to see that key again

		// loop resolving indirect references
		while (result != null) {
			if (result.value != null) {
				return result.value;
			}
			if (visitedKeys.contains(result.refId)) {
				Msg.warn(this, "Theme value reference loop detected for key: " + id);
				return getUnresolvedReferenceValue(id);
			}
			result = getReferredValue(values, result.refId);
		}
		return getUnresolvedReferenceValue(id);
	}

	abstract protected T getUnresolvedReferenceValue(String theId);

	abstract public String toExternalId(String internalId);

	abstract public String fromExternalId(String externalId);

	abstract protected ThemeValue<T> getReferredValue(GThemeValueMap preferredValues,
			String theRefId);

	@Override
	public int compareTo(ThemeValue<T> o) {
		return id.compareTo(o.id);
	}

	public int compareValue(ThemeValue<T> o) {
		if (o == null) {
			return -1;
		}
		if (refId != null) {
			return o.refId != null ? refId.compareTo(o.refId) : -1;
		}
		if (o.refId != null) {
			return 1;
		}
		return compareValues(value, o.value);
	}

	protected abstract int compareValues(T v1, T v2);

	@Override
	public int hashCode() {
		return Objects.hash(id, refId, value);
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
		ThemeValue<?> other = (ThemeValue<?>) obj;

		return Objects.equals(id, other.id) && Objects.equals(refId, other.refId) &&
			Objects.equals(value, other.value);
	}

	@Override
	public String toString() {
		String name = getClass().getSimpleName();
		if (refId == null) {
			return name + " (" + id + ", " + value + ")";
		}
		return name + " (" + id + ", " + refId + ")";
	}

}
