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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider.SetEmulatedBreakpointConditionAction;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.pcode.exec.SleighUtils;
import ghidra.util.HelpLocation;

public class DebuggerSleighExpressionInputDialog extends AbstractDebuggerSleighInputDialog {
	public static final DebuggerSleighExpressionInputDialog INSTANCE =
		new DebuggerSleighExpressionInputDialog();

	protected DebuggerSleighExpressionInputDialog() {
		super("Breakpoint Sleigh Condition", """
				<html>
				<p>Enter Emulated Breakpoint Sleigh Condition, e.g:</p>
				<ul>
				  <li><code>1:1</code> (Always)</li>
				  <li><code>0:1</code> (Never)</li>
				  <li><code>RAX == 7</code></li>
				</ul>
				<p>Press <b>F1</b> for help.</p>
				""");
		setHelpLocation(new HelpLocation(
			PluginUtils.getPluginNameFromClass(DebuggerBreakpointsPlugin.class),
			SetEmulatedBreakpointConditionAction.HELP_ANCHOR));
	}

	@Override
	protected void validate() {
		SleighUtils.parseSleighExpression(getInput());
	}
}
