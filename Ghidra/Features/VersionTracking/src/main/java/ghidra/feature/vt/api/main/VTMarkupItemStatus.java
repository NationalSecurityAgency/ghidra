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

public enum VTMarkupItemStatus {
	UNAPPLIED("Unapplied", true, false),
	ADDED("Applied (Added)", false, true),
	REPLACED("Applied (Replaced)", false, true),
	FAILED_APPLY("Apply Failed", false, false),
	DONT_CARE("Don't Care", true, false),
	DONT_KNOW("Don't Know", true, false),
	REJECTED("Rejected", false, false),
	SAME("Destination has same value", false, false),
	CONFLICT("Conflicting item is applied", false, false);

	private final String description;
	private boolean isAppliable;
	private boolean isUnappliable;

	private VTMarkupItemStatus(String description, boolean isAppliable, boolean isUnappliable) {
		this.description = description;
		this.isAppliable = isAppliable;
		this.isUnappliable = isUnappliable;
	}

	public boolean isAppliable() {
		return isAppliable;
	}

	public boolean isUnappliable() {
		return isUnappliable;
	}

	public boolean isDefault() {
		return this == SAME || this == CONFLICT || this == UNAPPLIED;
	}

	public String getDescription() {
		return description;
	}
}
