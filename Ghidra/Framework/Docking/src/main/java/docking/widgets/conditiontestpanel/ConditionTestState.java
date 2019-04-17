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
package docking.widgets.conditiontestpanel;

public class ConditionTestState {
	boolean enabled = true;
	ConditionResult result;
	private final ConditionTester conditionTest;

	public ConditionTestState(ConditionTester conditionTest) {
		this.conditionTest = conditionTest;

	}

	public String getName() {
		return conditionTest.getName();
	}

	public synchronized void setResult(ConditionResult result) {
		this.result = result;
	}

	public ConditionTester getConditionTest() {
		return conditionTest;
	}

	public ConditionStatus getStatus() {
		if (result != null) {
			return result.getStatus();
		}
		return ConditionStatus.None;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public String getStatusMessage() {
		if (result != null) {
			return result.getMessage();
		}
		return "";
	}

}
