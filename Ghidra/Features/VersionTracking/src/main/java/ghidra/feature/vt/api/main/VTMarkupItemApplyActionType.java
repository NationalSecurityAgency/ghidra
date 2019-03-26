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
package ghidra.feature.vt.api.main;

import static ghidra.feature.vt.api.main.VTMarkupItemStatus.ADDED;
import static ghidra.feature.vt.api.main.VTMarkupItemStatus.REPLACED;

public enum VTMarkupItemApplyActionType {

	ADD(ADDED),

	ADD_AS_PRIMARY(ADDED),

	/** Only replace the destination value when it is a default value */
	REPLACE_DEFAULT_ONLY(REPLACED),

	/** Always replaces the destination value */
	REPLACE(REPLACED),

	/** Replaces the destination value only if it won't overwrite other defined data beyond the first */
	REPLACE_FIRST_ONLY(REPLACED);

//	/** Only replace the destination value when the number of parameters is the same as in the source */
//	WHEN_SAME_PARAMETER_COUNT(REPLACED),
//
//	/** Replace the destination value whenever the function signature is replaced */
//	WHEN_TAKING_SIGNATURE(REPLACED);

	private final VTMarkupItemStatus status;

	private VTMarkupItemApplyActionType(VTMarkupItemStatus status) {
		this.status = status;
	}

	public VTMarkupItemStatus getApplyStatus() {
		return status;
	}

}
