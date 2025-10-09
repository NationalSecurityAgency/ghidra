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

import java.util.NoSuchElementException;

import ghidra.program.model.listing.Program;

/**
 * {@link SourceType} provides a prioritized indication as to the general source of a specific
 * markup made to a {@link Program}.  The priority of each defined source type may be used to 
 * restrict impact or protect the related markup.  Source types include: {@link #USER_DEFINED}, 
 * which is higher priority than {@link #IMPORTED}, which is higher priority than {@link #ANALYSIS},
 * which is higher priority than {@link #DEFAULT}.  The {@link #AI} source type is primarliy 
 * intended to allow AI generated markup to be identified and currently has the same priority 
 * as {@link #ANALYSIS}.
 */
public enum SourceType {
	// WARNING WARNING: the assigned storage IDs are used for persistent serialization.
	// Any change or re-use must consider data upgrade concerns.

	/** The object's source indicator for a default. */
	DEFAULT("Default", 1, 2),
	/** The object's source indicator for an auto analysis. */
	ANALYSIS("Analysis", 2, 0),
	/** The object's source indicator for something that was produced with AI assistance. */
	AI("AI", 2, 4),
	/** The object's source indicator for an imported. */
	IMPORTED("Imported", 3, 3),
	/** The object's source indicator for a user defined. */
	USER_DEFINED("User Defined", 4, 1);

	// SourceType values indexed by storageID (use null for undefined IDs).
	private static SourceType[] SOURCE_BY_STORAGE_ID =
		new SourceType[] { ANALYSIS, USER_DEFINED, DEFAULT, IMPORTED, AI };

	private final String displayString;
	private final int storageId;
	private final int priority; // bigger numbers are higher priority

	/**
	 * {@link SourceType} constructor
	 * @param displayString enum display name
	 * @param priority unique priority among other defined enum values
	 * @param storageId non-negative storage ID for persistent serialization.  Once an ID is 
	 * assigned it may never be removed without serious consideration to DB upgrade transformation.
	 */
	private SourceType(String displayString, int priority, int storageId) {
		this.displayString = displayString;
		this.storageId = storageId;
		this.priority = priority;
	}

	/**
	 * Get the SourceType which corresponds to the specified storage ID.
	 * @param storageId storage ID
	 * @return SourceType
	 * @throws NoSuchElementException if specified storage ID is not defined.
	 */
	public static SourceType getSourceType(int storageId) {
		try {
			SourceType source = SOURCE_BY_STORAGE_ID[storageId];
			if (source != null) {
				return source;
			}
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// throw error below
		}
		throw new NoSuchElementException("SourceType storgae ID not defined: " + storageId);
	}

	/**
	 * {@return numeric priority relative to other SourceType.  Higher numbers are higher priority.}
	 */
	public int getPriority() {
		return priority;
	}

	/**
	 * {@return the storage ID which should be used for persistent serialization}
	 */
	public int getStorageId() {
		return storageId;
	}

	/** 
	 * {@return a user-friendly string}
	 */
	public String getDisplayString() {
		return displayString;
	}

	/**
	 * Determine if this source type has a higher priority than the one being
	 * passed to this method as a parameter.
	 * @param source the source type whose priority is to be compared with this one's.
	 * @return true if this source type is a higher priority.
	 * false if this source type is the same priority or lower priority.
	 */
	public boolean isHigherPriorityThan(SourceType source) {
		return this.priority > source.priority;
	}

	/**
	 * Determine if this source type has the same or higher priority than the one being
	 * passed to this method as a parameter.
	 * @param source the source type whose priority is to be compared with this one's.
	 * @return true if this source type is a higher priority.
	 * false if this source type is the same priority or lower priority.
	 */
	public boolean isHigherOrEqualPriorityThan(SourceType source) {
		return this.priority >= source.priority;
	}

	/**
	 * Determine if this source type has a lower priority than the one being
	 * passed to this method as a parameter.
	 * @param source the source type whose priority is to be compared with this one's.
	 * @return true if this source type is a lower priority.
	 * false if this source type is the same priority or higher priority.
	 */
	public boolean isLowerPriorityThan(SourceType source) {
		return this.priority < source.priority;
	}

	/**
	 * Determine if this source type has the same or lower priority than the one being
	 * passed to this method as a parameter.
	 * @param source the source type whose priority is to be compared with this one's.
	 * @return true if this source type is a lower priority.
	 * false if this source type is the same priority or higher priority.
	 */
	public boolean isLowerOrEqualPriorityThan(SourceType source) {
		return this.priority <= source.priority;
	}
}
