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

package ghidra.app.plugin.core.pcodepatch;

import ghidra.app.context.ListingActionContext;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

public class PcodePatchRemoveAction extends AbstractPcodeManipulationAction {

    public PcodePatchRemoveAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner, plugin);
    }

    @Override
    protected boolean isEnabledForContext(ListingActionContext context) {
        return super.isEnabledForContext(context) && instruction.hasPatch();
    }

    @Override
    protected void initialAction() {

        Program program = this.plugin.getCurrentProgram();
        
        this.plugin.getTool().execute(new BackgroundCommand() {

                @Override
                public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
                    try {
                        Disassembler disassembler = Disassembler.getDisassembler(
                            program, monitor, DisassemblerMessageListener.IGNORE);
                        instruction.removePatchedPcode();
                        Address addr = instruction.getAddress();
                        disassembler.disassemble(addr, new AddressSet(addr));
                        return true;
                    } catch (Exception e) {
                        Msg.showError(this, null, "Can't Remove Pcode Patch", e.toString());
                        return false;
                    }
                }

                @Override
                public String getStatusMsg() {
                    return null;
                }

                @Override
                public String getName() {
                    return "PcodePatchRemove";
                }

            }, program);
    }
}
