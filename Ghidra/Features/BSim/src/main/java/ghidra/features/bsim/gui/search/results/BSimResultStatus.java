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
package ghidra.features.bsim.gui.search.results;

/**
 * Enum of BSim results apply statuses for when users attempt to apply function names or signatures
 */
public enum BSimResultStatus {
	NOT_APPLIED("This result has not been applied."),
	NAME_APPLIED("The name and namespace have been applied."),
	SIGNATURE_APPLIED("The name, namespace and signature have been applied."),
	MATCHES("The name already matches."),
	APPLIED_NO_LONGER_MATCHES("This result has been applied, but no longer matches!"),
	ERROR("An error occurred while attempting to apply this result."),
	NO_FUNCTION("There is no longer a function at the result address!"),
	IGNORED("The result was not applied because it already matched.");

	private String description;

	BSimResultStatus(String description) {
		this.description = description;
	}

	public String getDescription() {
		return description;
	}
}
