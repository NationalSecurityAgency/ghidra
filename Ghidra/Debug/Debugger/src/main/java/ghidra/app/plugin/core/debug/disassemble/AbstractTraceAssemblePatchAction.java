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

import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.assembler.AbstractAssemblePatchDialog;
import ghidra.app.plugin.core.assembler.AssemblePatchAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;

public abstract class AbstractTraceAssemblePatchAction extends AssemblePatchAction {

	public AbstractTraceAssemblePatchAction(DebuggerDisassemblerPlugin plugin, String name) {
		super(plugin, name);
	}

	protected abstract TracePlatform getPlatform(TraceProgramView view, Address entry);

	@Override
	protected AbstractAssemblePatchDialog<?> newDialog(ListingActionContext ctx) {
		if (!(ctx.getProgram() instanceof TraceProgramView view)) {
			return null;
		}
		Address entry = ctx.getAddress();
		Instruction ins = view.getListing().getInstructionContaining(entry);
		RegisterValue initialContext = getInitialContext(ins, view, entry);
		return new TraceAssemblePatchDialog(plugin.getTool(), ctx.getNavigatable(),
			getPlatform(view, entry), view, entry, initialContext);
	}
}
