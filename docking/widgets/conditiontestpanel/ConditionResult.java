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

public class ConditionResult {
	private final ConditionStatus status;
	private final String message;

	public ConditionResult(ConditionStatus status) {
		this(status, null);
	}

	public ConditionResult(ConditionStatus status, String message) {
		this.status = status;
		this.message = message;
	}

	public ConditionStatus getStatus() {
		return status;
	}

	public String getMessage() {
		if (message == null || message.matches("^\\s*$")) {
			return getDefaultMessage();
		}
		return message;
	}

	private String getDefaultMessage() {
		switch (status) {
			case Cancelled:
				return "Cancelled by user";
			case Error:
				return "Error - please update test to provide a better error message";
			case None:
				return "";
			case Passed:
				return "Passed";
			case Skipped:
				return "Skipped";
			case Warning:
				return "Warning - please update test to provide a better warning message";
		}
		return "";
	}
}
