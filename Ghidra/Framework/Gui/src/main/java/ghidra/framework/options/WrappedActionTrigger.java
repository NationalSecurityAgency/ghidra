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
package ghidra.framework.options;

import java.util.Objects;

public class WrappedActionTrigger implements WrappedOption {

	private ActionTrigger actionTrigger;

	/**
	 * Default constructor
	 */
	WrappedActionTrigger() {
		// for reflection
	}

	/**
	 * Construct a wrapper object using the given ActionTrigger.
	 * @param actionTrigger the action trigger
	 */
	WrappedActionTrigger(ActionTrigger actionTrigger) {
		this.actionTrigger = actionTrigger;
	}

	@Override
	public Object getObject() {
		return actionTrigger;
	}

	@Override
	public void readState(SaveState saveState) {
		actionTrigger = ActionTrigger.create(saveState);
	}

	@Override
	public void writeState(SaveState saveState) {
		if (actionTrigger == null) {
			return;
		}

		actionTrigger.writeState(saveState);
	}

	@Override
	public OptionType getOptionType() {
		return OptionType.ACTION_TRIGGER;
	}

	@Override
	public String toString() {
		return Objects.toString(actionTrigger);
	}
}
