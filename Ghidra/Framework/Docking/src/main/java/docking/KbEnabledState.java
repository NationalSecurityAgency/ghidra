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
package docking;

/**
 * A class to track an action's precedence and enablement
 * @param precedence the precedence
 * @param isValid true if valid
 * @param isEnabled true if enabled
 */
public record KbEnabledState(KeyBindingPrecedence precedence, boolean isValid,
		boolean isEnabled) {

	public KbEnabledState {
		if (!isValid && isEnabled) {
			throw new IllegalArgumentException("Cannot be enable if not also valid");
		}
	}
}
