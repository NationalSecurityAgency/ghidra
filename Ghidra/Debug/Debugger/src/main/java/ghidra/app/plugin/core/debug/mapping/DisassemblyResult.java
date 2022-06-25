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
package ghidra.app.plugin.core.debug.mapping;

public class DisassemblyResult {
	public static final DisassemblyResult SUCCESS = new DisassemblyResult(true, null);
	public static final DisassemblyResult CANCELLED = new DisassemblyResult(false, null);

	public static DisassemblyResult failed(String errorMessage) {
		return new DisassemblyResult(false, errorMessage);
	}

	public static DisassemblyResult success(boolean atLeastOne) {
		return atLeastOne ? SUCCESS : CANCELLED;
	}

	private final boolean atLeastOne;
	private final String errorMessage;

	public DisassemblyResult(boolean atLeastOne, String errorMessage) {
		this.atLeastOne = atLeastOne;
		this.errorMessage = errorMessage;
	}

	public boolean isAtLeastOne() {
		return atLeastOne;
	}

	public boolean isSuccess() {
		return errorMessage == null;
	}

	public String getErrorMessage() {
		return errorMessage;
	}
}
