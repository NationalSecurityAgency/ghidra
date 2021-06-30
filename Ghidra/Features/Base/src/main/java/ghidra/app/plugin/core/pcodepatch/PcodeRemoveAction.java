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

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.RawPcode;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class PcodeRemoveAction extends AbstractPcodeManipulationAction {
    public PcodeRemoveAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner, plugin);
    }

    @Override
    protected void initialAction() {
        Program program = this.plugin.getCurrentProgram();

        this.plugin.getTool().execute(new BackgroundCommand() {

            @Override
            public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
                try {
                    List<RawPcode> pcode = Stream.of(instruction.getPcode())
                        .collect(Collectors.toList());
                    pcode.remove(row);
                    instruction.patchPcode(pcode.toArray(RawPcode[]::new));
                    return true;
                } catch (Exception e) {
                    Msg.showError(this, null, "Can't Remove Pcode", e.toString());
                    return false;
                }
            }

        }, program);
    }
}
