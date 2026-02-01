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
package ghidra.app.plugin.core.go.dialog;

public class GhidraGoWaitForListenerDialog extends GhidraGoWaitDialog {

	public GhidraGoWaitForListenerDialog() {
		super("GhidraGo Taking Longer Than Expected to Listen",
			"If Ghidra has started, please confirm the GhidraGoPlugin has been added in " +
				"File->Configure in the Ghidra project manager.\n" +
				"If GhidraGoPlugin has been configured, make sure Ghidra has an active project.\n" +
				"Would you like to keep waiting?",
			true);
	}

}
