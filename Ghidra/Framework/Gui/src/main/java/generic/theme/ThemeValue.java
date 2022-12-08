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
	protected final String id;
	protected final T value;
	protected final String referenceId;

	protected ThemeValue(String id, String referenceId, T value) {
		if (id.equals(referenceId)) {
			throw new IllegalArgumentException("Can't create a themeValue that referencs itself");
		}
		this.id = id;
		this.referenceId = referenceId;
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
		return referenceId;
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
	 * preferredValues map to resolve references. If the value can't be resolved by following
	 * reference chains, an error stack trace will be generated and the default T value will
	 * be returned. In rare situations where it is acceptable for the value to not be resolvable,
	 * use the {@link #hasResolvableValue(GThemeValueMap)} method first.
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
		ThemeValue<T> referred = getReferredValue(values, referenceId);

		// loop resolving indirect references
		while (referred != null) {
			if (referred.value != null) {
				return referred.get(values);
			}
			visitedKeys.add(referred.id);
			if (visitedKeys.contains(referred.referenceId)) {
				Msg.warn(this, "Theme value reference loop detected for key: " + id);
				return getUnresolvedReferenceValue(id, referred.referenceId);
			}
			referred = getReferredValue(values, referred.referenceId);
		}
		return getUnresolvedReferenceValue(id, referenceId);
	}

	/**
	 * Returns true if the ThemeValue can resolve to the concrete T value (color, font, or icon)
	 * from the given set of theme values.
	 * @param values the set of values to use to try and follow reference chains to ultimately
	 * resolve the ThemeValue to a an actual T value 
	 * @return true if the ThemeValue can resolve to the concrete T value (color, font, or icon)
	 * from the given set of theme values.
	 */
	public boolean hasResolvableValue(GThemeValueMap values) {
		if (value != null) {
			return true;
		}

		Set<String> visitedKeys = new HashSet<>();
		visitedKeys.add(id);
		ThemeValue<T> referred = getReferredValue(values, referenceId);

		// loop resolving indirect references
		while (referred != null) {
			if (referred.value != null) {
				return true;
			}
			visitedKeys.add(referred.id);
			if (visitedKeys.contains(referred.referenceId)) {
				Msg.warn(this, "Theme value reference loop detected for key: " + id);
				return false;
			}
			referred = getReferredValue(values, referred.referenceId);
		}
		return false;
	}

	/**
	 * Returns true if this ThemeValue derives its value from the given ancestorId.
	 * @param ancestorId the id to test if this Theme value inherits from
	 * @param values the set of values used to resolve indirect references to attempt to trace
	 * back to the given ancestor id
	 * @return true if this ThemeValue derives its value from the given ancestorId.
	 */
	public boolean inheritsFrom(String ancestorId, GThemeValueMap values) {
		if (referenceId == null) {
			return false;
		}
		if (referenceId.equals(ancestorId)) {
			return true;
		}

		Set<String> visitedKeys = new HashSet<>();
		visitedKeys.add(id);
		ThemeValue<T> parent = getReferredValue(values, referenceId);

		// loop resolving indirect references
		while (parent != null) {
			if (parent.referenceId == null) {
				return false;
			}
			if (parent.referenceId.equals(ancestorId)) {
				return true;
			}
			visitedKeys.add(parent.id);
			if (visitedKeys.contains(parent.referenceId)) {
				return false;
			}
			parent = getReferredValue(values, parent.referenceId);
		}
		return false;
	}

	/**
	 * Returns true if this ColorValue gets its value from some other ColorValue
	 * @return  true if this ColorValue gets its value from some other ColorValue
	 */
	public boolean isIndirect() {
		return referenceId != null;
	}

	/**
	 * Returns the "key = value" String for writing this ThemeValue to a file
	 * @return the "key = value" String for writing this ThemeValue to a file
	 */
	public abstract String getSerializationString();

	/**
	 * Returns the T to be used if the indirect reference couldn't be resolved.
	 * @param id the id we are trying to get a value foe
	 * @param unresolvedId the reference id that couldn't be resolved 
	 * @return the default value to be used if the indirect reference couldn't be resolved.
	 */
	protected abstract T getUnresolvedReferenceValue(String id, String unresolvedId);

	/**
	 * Returns the ThemeValue referred to by this ThemeValue. Needs to be overridden by
	 * concrete classes as they know the correct method to call on the preferredValues map.
	 * @param preferredValues the {@link GThemeValueMap} to be used to resolve the reference id
	 * @param refId  the id of the reference ThemeValue
	 * @return the ThemeValue referred to by this ThemeValue.
	 */
	protected abstract ThemeValue<T> getReferredValue(GThemeValueMap preferredValues,
			String refId);

	@Override
	public int compareTo(ThemeValue<T> o) {
		return id.compareTo(o.id);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, referenceId, value);
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

		return Objects.equals(id, other.id) && Objects.equals(referenceId, other.referenceId) &&
			Objects.equals(value, other.value);
	}

	@Override
	public String toString() {
		String name = getClass().getSimpleName();
		if (referenceId == null) {
			return name + " (" + id + ", " + value + ")";
		}
		return name + " (" + id + ", " + referenceId + ")";
	}

	/**
	 * Install this value as the current value for the application
	 * @param themeManager the application ThemeManager
	 */
	public abstract void installValue(ThemeManager themeManager);

}
