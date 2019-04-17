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
package ghidra.feature.vt.gui.util;

import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTMarkupItemStatus;

/**
 * This status is a combination of the {@link VTAssociationStatus} and the 
 * {@link VTMarkupItemStatus}.  This class exists for UI purposes, such as rendering and sorting.
 */
public enum MungedAssocationAndMarkupItemStatus {

	AVAILABLE("This match is available to be applied"),
	ACCEPTED_HAS_ERRORS("One or more markup errors"),
	ACCEPTED_SOME_UNEXAMINED("One or more markup items have not been considered"),
	ACCEPTED_NO_UNEXAMINED("All markup items have been applied or ignored"),
	ACCEPTED_FULLY_APPLIED("All markup items applied"),
	BLOCKED("This match is blocked by an already accepted conflicting match"),
	REJECTED("Rejected");

	private final String description;

	MungedAssocationAndMarkupItemStatus(String description) {
		this.description = description;
	}

	public String getDescription() {
		return description;
	}
}
