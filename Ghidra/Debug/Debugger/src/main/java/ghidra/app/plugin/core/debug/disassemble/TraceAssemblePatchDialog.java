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

import java.util.List;

import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.assembler.AbstractAssemblePatchDialog;
import ghidra.app.plugin.core.assembler.AbstractPatchAssemblyCommand;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;

public class TraceAssemblePatchDialog extends AbstractAssemblePatchDialog<TraceProgramView> {
	private final TracePlatform platform;

	protected TraceAssemblePatchDialog(PluginTool tool, Navigatable navigatable,
			TracePlatform platform, TraceProgramView program, Address entry,
			RegisterValue initialContext) {
		this.platform = platform;
		super(tool, navigatable, program, entry, initialContext);
	}

	@Override
	protected AbstractPatchAssemblyCommand<TraceProgramView> newPatchCommand(List<String> lines) {
		return new TracePatchAssemblyCommand(platform, assembler, lines, entry, initialContext);
	}

	@Override
	protected Language getLanguage() {
		return platform.getLanguage();
	}

	@Override
	protected Assembler getAssembler() {
		return Assemblers.getAssembler(getLanguage());
	}
}
