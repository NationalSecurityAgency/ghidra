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

/**
 * A generic class for storing theme values that have a String id (e.g. color.bg.foo) and either
 * a concrete value of type T or a reference id which is the String id of another ThemeValue. So
 * if this class's value is non-null, the refId will be null and if the class's refId is non-null,
 * then the value will be null.
 *
 * @param <T> the base type this ThemeValue works on (i.e., Colors, Fonts, Icons)
 */
public abstract class ThemeValue<T> implements Comparable<ThemeValue<T>> {
	private final String id;
	private final T value;
	private final String refId;

	protected ThemeValue(String id, String refId, T value) {
		this.id = fromExternalId(id);
		this.refId = (refId == null) ? null : fromExternalId(refId);
		this.value = value;
	}

	/**
	 * Returns the identifier for this ThemeValue.
	 * @return the identifier for this ThemeValue.
	 */
	public String getId() {
		return id;
	}

	/**
	 * Returns the referencId of another ThemeValue that we inherit its value pr null if we have
	 * a value
	 * 
	 * @return  the referencId of another ThemeValue that we inherit its value or null if we have
	 * a value
	 */
	public String getReferenceId() {
		return refId;
	}

	/**
	 * Returns the stored value. Does not follow referenceIds. Will be null if this instance
	 * has a referenceId.
	 * 
	 * @return the stored value. Does not follow referenceIds. Will be null if this instance
	 * has a referenceId.
	 */
	public T getRawValue() {
		return value;
	}

	/**
	 * Returns the T value for this instance, following references as needed. Uses the given
	 * preferredValues map to resolve references.
	 * @param values the {@link GThemeValueMap} used to resolve references if this 
	 * instance doesn't have an actual value.
	 * @return the T value for this instance, following references as needed.
	 */
	public T get(GThemeValueMap values) {
		if (value != null) {
			return value;
		}

		Set<String> visitedKeys = new HashSet<>();
		visitedKeys.add(id);
		ThemeValue<T> parent = getReferredValue(values, refId);

		// loop resolving indirect references
		while (parent != null) {
			if (parent.value != null) {
				return parent.value;
			}
			visitedKeys.add(parent.id);
			if (visitedKeys.contains(parent.refId)) {
				Msg.warn(this, "Theme value reference loop detected for key: " + id);
				return getUnresolvedReferenceValue(id);
			}
			parent = getReferredValue(values, parent.refId);
		}
		return getUnresolvedReferenceValue(id);
	}

	public boolean inheritsFrom(String ancestorId, GThemeValueMap values) {
		if (refId == null) {
			return false;
		}
		if (refId.equals(ancestorId)) {
			return true;
		}

		Set<String> visitedKeys = new HashSet<>();
		visitedKeys.add(id);
		ThemeValue<T> parent = getReferredValue(values, refId);

		// loop resolving indirect references
		while (parent != null) {
			if (parent.refId == null) {
				return false;
			}
			if (parent.refId.equals(ancestorId)) {
				return true;
			}
			visitedKeys.add(parent.id);
			if (visitedKeys.contains(parent.refId)) {
				return false;
			}
			parent = getReferredValue(values, parent.refId);
		}
		return false;
	}

	/**
	 * Returns the T to be used if the indirect reference couldn't be resolved.
	 * @param unresolvedId the id that couldn't be resolved 
	 * @return the default value to be used if the indirect reference couldn't be resolved.
	 */
	abstract protected T getUnresolvedReferenceValue(String unresolvedId);

	/**
	 * Returns the id to be used when writing to a theme file. For ThemeValues whose id begins
	 * with the expected prefix (e.g. "color" for ColorValues), it is just the id. Otherwise, the
	 * id is prepended with an appropriate string to make parsing easier.
	 * @param internalId the id of this ThemeValue
	 * @return the id to be used when writing to a theme file
	 */
	abstract public String toExternalId(String internalId);

	/**
	 * Converts an external id to an internal id (the id stored in this object)
	 * @param externalId the external form of the id
	 * @return the id for the ThemeValue being read from a file
	 */
	abstract public String fromExternalId(String externalId);

	/**
	 * Returns the ThemeValue referred to by this ThemeValue. Needs to be overridden by
	 * concrete classes as they know the correct method to call on the preferredValues map.
	 * @param preferredValues the {@link GThemeValueMap} to be used to resolve the reference id
	 * @param referenceId  the id of the reference ThemeValue
	 * @return the ThemeValue referred to by this ThemeValue.
	 */
	abstract protected ThemeValue<T> getReferredValue(GThemeValueMap preferredValues,
			String referenceId);

	@Override
	public int compareTo(ThemeValue<T> o) {
		return id.compareTo(o.id);
	}

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
