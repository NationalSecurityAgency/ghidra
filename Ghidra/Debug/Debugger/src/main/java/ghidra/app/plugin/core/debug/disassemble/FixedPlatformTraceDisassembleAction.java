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
package ghidra.app.plugin.core.debug.disassemble;

import docking.action.MenuData;
import ghidra.program.model.lang.LanguageID;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;

public class FixedPlatformTraceDisassembleAction extends AbstractTraceDisassembleAction {
	private final LanguageID altLangID;
	private final TracePlatform platform;

	public FixedPlatformTraceDisassembleAction(DebuggerDisassemblerPlugin plugin,
			LanguageID altLangID, TracePlatform platform) {
		super(plugin, "Disassemble Trace as " + altLangID);
		this.altLangID = altLangID;
		this.platform = platform;

		// TODO: Human-readable description?
		setPopupMenuData(
			new MenuData(new String[] { "Disassemble as " + altLangID }, "Disassembly"));
	}

	@Override
	protected TracePlatform getPlatform(TraceProgramView view) {
		return platform;
	}

	@Override
	protected LanguageID getAlternativeLanguageID() {
		return altLangID;
	}
}
