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
package ghidra.app.plugin.core.debug.gui.objects.components;

import static org.junit.Assert.assertNotNull;

import java.util.Map;

import docking.test.AbstractDockingTest;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.util.Swing;

public class InvocationDialogHelper {

	public static InvocationDialogHelper waitFor() {
		DebuggerMethodInvocationDialog dialog =
			AbstractDockingTest.waitForDialogComponent(DebuggerMethodInvocationDialog.class);
		return new InvocationDialogHelper(dialog);
	}

	private final DebuggerMethodInvocationDialog dialog;

	public InvocationDialogHelper(DebuggerMethodInvocationDialog dialog) {
		this.dialog = dialog;
	}

	public void dismissWithArguments(Map<String, Object> args) {
		for (Map.Entry<String, Object> a : args.entrySet()) {
			ParameterDescription<?> p = dialog.parameters.get(a.getKey());
			assertNotNull(p);
			dialog.setMemorizedArgument(a.getKey(), p.type.asSubclass(Object.class), a.getValue());
		}
		Swing.runNow(() -> dialog.invoke(null));
	}
}
