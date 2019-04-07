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
package help.screenshot;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import docking.DialogComponentProvider;
import docking.widgets.conditiontestpanel.ConditionTestModel;
import ghidra.app.plugin.core.validator.ValidateProgramPlugin;

public class ValidateProgramScreenShots extends GhidraScreenShotGenerator {

	public ValidateProgramScreenShots() {
		super();
	}

@Test
    public void testValidateProgram() {

		loadPlugin(ValidateProgramPlugin.class);

		performAction("Validate Program", "ValidateProgramPlugin", false);
		waitForPostedSwingRunnables();

		captureDialog();
	}

@Test
	public void testValidateProgramDone() {

		loadPlugin(ValidateProgramPlugin.class);

		performAction("Validate Program", "ValidateProgramPlugin", false);
		waitForPostedSwingRunnables();

		DialogComponentProvider dialog = getDialog();
		pressButtonByText(dialog, "Run Validators");

		Object conditionTestPanel = getInstanceField("conditionTestPanel", dialog);
		ConditionTestModel model =
			(ConditionTestModel) getInstanceField("conditionTestModel", conditionTestPanel);

		waitForValidators(model);

		captureDialog();
	}

	private void waitForValidators(ConditionTestModel model) {
		int sleepyTime = 100;
		int totalTime = 0;
		while (model.isInProgress() && totalTime < 10000) {
			sleep(sleepyTime);
			totalTime += sleepyTime;
		}

		assertTrue("Timed out waiting for condition tests", totalTime < 10000);
	}
}
