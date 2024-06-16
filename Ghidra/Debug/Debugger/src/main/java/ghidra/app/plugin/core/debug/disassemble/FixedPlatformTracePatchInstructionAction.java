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

import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.model.guest.TracePlatform;

public class FixedPlatformTracePatchInstructionAction extends AbstractTracePatchInstructionAction {
	private final LanguageID altLangID;
	private final TracePlatform platform;

	public FixedPlatformTracePatchInstructionAction(DebuggerDisassemblerPlugin plugin,
			LanguageID altLangID, TracePlatform platform) {
		super(plugin, "Patch Instruction using " + altLangID);
		setKeyBindingData(null);

		this.altLangID = altLangID;
		this.platform = platform;
	}

	@Override
	protected TracePlatform getPlatform(CodeUnit cu) {
		return platform;
	}

	@Override
	protected LanguageID getAlternativeLanguageID(CodeUnit cu) {
		return altLangID;
	}
}
