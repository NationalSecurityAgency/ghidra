/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.api.main;

import static ghidra.feature.vt.api.main.VTMarkupItemStatus.*;

/**
 * A status that the user can set on an item to signal that the item has been considered, but not
 * applied.  This is useful for markup items that the user knows are incorrect or doesn't care 
 * about.  By setting the considered status of a markup item to one of these values, then 
 * the user can filter out items based upon that status.
 * 
 * @see VTMarkupItem#setConsidered(VTMarkupItemConsideredStatus)
 */
public enum VTMarkupItemConsideredStatus {

	/**
	 * Indicates that a markup item has not been considered.  This value exists in order to 
	 * reset one of the other values in this enum.
	 */
	UNCONSIDERED(UNAPPLIED),

	/**
	 * Indicates that a markup item should be ignored because the user doesn't know if it should
	 * be applied.
	 */
	IGNORE_DONT_KNOW(DONT_KNOW),

	/**
	 * Indicates that a markup item should be ignored because the user doesn't care if it should
	 * be applied.
	 */
	IGNORE_DONT_CARE(DONT_CARE),

	/**
	 * Indicates that the markup item should not be applied.
	 */
	REJECT(REJECTED);

	private final VTMarkupItemStatus status;

	private VTMarkupItemConsideredStatus(VTMarkupItemStatus status) {
		this.status = status;

	}

	/**
	 * The status applied to the markup item when 
	 * {@link VTMarkupItem#setConsidered(VTMarkupItemConsideredStatus)} is called.
	 */
	public VTMarkupItemStatus getMarkupItemStatus() {
		return status;
	}
}
