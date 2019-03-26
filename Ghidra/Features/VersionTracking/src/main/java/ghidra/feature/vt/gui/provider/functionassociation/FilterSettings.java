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
package ghidra.feature.vt.gui.provider.functionassociation;

import ghidra.feature.vt.api.main.VTAssociationStatus;

/**
 * Enum to describe the filter settings for the {@link VTFunctionAssociationProvider}.
 */
public enum FilterSettings {

	/**
	 * Indicates to show all functions (no filtering).
	 */
	SHOW_ALL,

	/**
	 * Indicates to show only functions that are not part of a match.
	 */
	SHOW_UNMATCHED,

	/**
	 * Indicates to show only functions that are 1) not part of a match or 2) part of a match 
	 * that has not been {@link VTAssociationStatus#ACCEPTED}.
	 */
	SHOW_UNACCEPTED
}
