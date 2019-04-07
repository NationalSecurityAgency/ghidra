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

/**
 * Interface used for a callback when associations are accepted or cleared. 
 */
public interface AssociationHook {
	/**
	 * Called whenever an association has been accepted.
	 * @param association the association that has been accepted.
	 */
	public void associationAccepted(VTAssociation association);

	/**
	 * Called whenever an association has been cleared from the accepted state.
	 * @param association the association that has been cleared from the accpeted state.
	 */
	public void associationCleared(VTAssociation association);

	/**
	 * Called whenever a markupItem's status changes.
	 * @param markupItem the markupItem that changed.
	 */
	public void markupItemStatusChanged(VTMarkupItem markupItem);
}
