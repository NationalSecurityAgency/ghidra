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

import java.util.stream.Stream;

import ghidra.program.model.pcode.RawPcodeImpl;
import ghidra.program.model.pcode.RawPcode;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeRawFormatter;


public class PcodePatchAction extends AbstractPcodePatchAction {

    private PatchPcodeTextDialog dialog;

    public PcodePatchAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner, plugin);

        this.dialog = new PatchPcodeTextDialog(plugin, this);
    }

    @Override
    protected void showDialog() {
        PcodeOp curPcode = instruction.getPcode()[row];
        this.dialog.show(PcodeRawFormatter.formatSingleRaw(curPcode));
    }

    @Override
    public void doPatch(RawPcodeImpl patchPcode) {
        RawPcode[] pcodes = Stream.of(instruction.getPcode()).toArray(RawPcode[]::new);
        pcodes[row] = patchPcode;
        instruction.patchPcode(pcodes);
    }
}
