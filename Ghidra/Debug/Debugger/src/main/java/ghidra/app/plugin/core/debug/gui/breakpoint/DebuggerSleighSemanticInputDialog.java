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

import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider.SetEmulatedBreakpointInjectionAction;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.pcode.exec.SleighUtils;
import ghidra.util.HelpLocation;

public class DebuggerSleighSemanticInputDialog extends AbstractDebuggerSleighInputDialog {
	public static final DebuggerSleighSemanticInputDialog INSTANCE =
		new DebuggerSleighSemanticInputDialog();

	protected DebuggerSleighSemanticInputDialog() {
		super("Breakpoint Sleigh Injection", """
				<html>
				<p>Enter Emulated Breakpoint Sleigh Injection, e.g., an unconditional break:</p>
				<pre>
				emu_swi();
				emu_exec_decoded();
				</pre>
				<p>Press <b>F1</b> for help and more examples.</p>
				<p><b>Be sure to include control flow, or the emulator may get stuck!</b></p>
				""");
		setHelpLocation(new HelpLocation(
			PluginUtils.getPluginNameFromClass(DebuggerBreakpointsPlugin.class),
			SetEmulatedBreakpointInjectionAction.HELP_ANCHOR));
	}

	@Override
	protected void validate() {
		SleighUtils.parseSleighSemantic(getInput());
	}
}
