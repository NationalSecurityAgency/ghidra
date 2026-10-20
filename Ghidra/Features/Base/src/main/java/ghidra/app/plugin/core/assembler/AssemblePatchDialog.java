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
package ghidra.app.plugin.core.assembler;

import java.util.List;

import ghidra.app.nav.Navigatable;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;

public class AssemblePatchDialog extends AbstractAssemblePatchDialog<Program> {

	protected AssemblePatchDialog(PluginTool tool, Navigatable navigatable, Program program,
			Address entry, RegisterValue initialContext) {
		super(tool, navigatable, program, entry, initialContext);
	}

	@Override
	protected AbstractPatchAssemblyCommand<Program> newPatchCommand(List<String> lines) {
		return new PatchAssemblyCommand(assembler, lines, entry, initialContext);
	}
}
