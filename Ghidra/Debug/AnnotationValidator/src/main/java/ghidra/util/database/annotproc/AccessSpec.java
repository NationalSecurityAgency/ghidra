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
package ghidra.util.database.annotproc;

import java.util.Set;

import javax.lang.model.element.Modifier;

public enum AccessSpec {
	PRIVATE(0), PACKAGE(1), PROTECTED(2), PUBLIC(3);

	private final int level;

	private AccessSpec(int level) {
		this.level = level;
	}

	/**
	 * Checks if the second permits the same or more access than the first
	 * 
	 * @param first the first
	 * @param second the second
	 * @return true if the second is the same or more permissive
	 */
	public static boolean isSameOrMorePermissive(AccessSpec first, AccessSpec second) {
		// TODO: I'm not sure protected actually includes package...
		// It might be more diamond shaped
		return first.level <= second.level;
	}

	/**
	 * Get the access specifier derived from the given modifiers
	 * 
	 * @param modifiers the element's modifiers
	 * @return the elements access specification
	 */
	public static AccessSpec get(Set<Modifier> modifiers) {
		if (modifiers.contains(Modifier.PRIVATE)) {
			return PRIVATE;
		}
		if (modifiers.contains(Modifier.PROTECTED)) {
			return PROTECTED;
		}
		if (modifiers.contains(Modifier.PUBLIC)) {
			return PUBLIC;
		}
		return PACKAGE;
	}
}
