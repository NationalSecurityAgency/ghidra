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
package ghidra.app.plugin.core.debug.gui.action;

import ghidra.program.model.address.Address;

public record GoToInput(String space, String offset) {
	public static GoToInput fromString(String string) {
		if (string.contains(":")) {
			String[] parts = string.split(":", 2);
			return new GoToInput(parts[0], parts[1]);
		}
		return new GoToInput(null, string);
	}

	public static GoToInput fromAddress(Address address) {
		return new GoToInput(address.getAddressSpace().getName(), address.toString(false));
	}

	public static GoToInput offsetOnly(String offset) {
		return new GoToInput(null, offset);
	}
}
