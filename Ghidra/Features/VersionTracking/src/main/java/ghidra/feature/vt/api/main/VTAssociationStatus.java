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

public enum VTAssociationStatus {

	/** 
	 * An association with this status is available for accepting (applying).  Also,
	 * no competing associations are currently {@link #ACCEPTED}.
	 */
	AVAILABLE("Available"),

	/** 
	 * An association with this status means no other competing associations can add markup
	 * items.  Any competing associations cannot have markup items applied while 
	 * one of them has this status. In this status, not all markup items have been applied, as 
	 * the status would then be {@link #FULLY_APPLIED}.
	 */
	ACCEPTED("Accepted"),

	/**
	 * A competing association has been accepted and an association with this status cannot be
	 * accepted.
	 */
	BLOCKED("Blocked"),

	/**
	 * The user has explicitly rejected this association.
	 */
	REJECTED("Rejected");

	private final String displayName;

	private VTAssociationStatus(String displayName) {
		this.displayName = displayName;
	}

	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Convenience method that returns true if match with this status can transition to the
	 * accepted status.
	 * @return true if match with this status can transition to the
	 * accepted status.
	 */
	public boolean canApply() {
		return this == ACCEPTED || this == AVAILABLE;
	}

	/**
	 * Convenience method that returns true if match with this status cannot be transitioned to
	 * an accepted status.
	 * @return true if match with this status cannot be transitioned to
	 * an accepted status.
	 */
	public boolean isBlocked() {
		return this == BLOCKED || this == REJECTED;
	}
}
