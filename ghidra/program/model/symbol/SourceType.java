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
package ghidra.program.model.symbol;

public enum SourceType {
	// WARNING WARNING: do not change the order of these enums as they are stored in the
	// database by their ordinal.

	/** The object's source indicator for an auto analysis. */
	ANALYSIS("Analysis", 2),
	/** The object's source indicator for a user defined. */
	USER_DEFINED("User Defined", 4),
	/** The object's source indicator for a default. */
	DEFAULT("Default", 1),
	/** The object's source indicator for an imported. */
	IMPORTED("Imported", 3);

	private final String displayString;
	private final int priority; // bigger numbers are higher priorty

	private SourceType(String displayString, int priority) {
		this.displayString = displayString;
		this.priority = priority;
	}

	/** Returns a user-friendly string */
	public String getDisplayString() {
		return displayString;
	}

	/**
	 * Determines if this source type is a higher priority than the one being
	 * passed to this method as a parameter.
	 * USER_DEFINED objects are higher priority than IMPORTED objects which are higher
	 * priority than ANALYSIS objects which are higher priority than DEFAULT objects.
	 * @param source the source type whose priority is to be compared with this one's.
	 * @return true if this source type is a higher priority.
	 * false if this source type is the same priority or lower priority.
	 */
	public boolean isHigherPriorityThan(SourceType source) {
		return this.priority > source.priority;
	}

	/**
	 * Determines if this source type is a lower priority than the one being
	 * passed to this method as a parameter.
	 * DEFAULT objects are lower priority than ANALYSIS objects which are lower
	 * priority than IMPORTED objects which are lower priority than USER_DEFINED objects.
	 * @param source the source type whose priority is to be compared with this one's.
	 * @return true if this source type is a lower priority.
	 * false if this source type is the same priority or higher priority.
	 */
	public boolean isLowerPriorityThan(SourceType source) {
		return this.priority < source.priority;
	}
}
