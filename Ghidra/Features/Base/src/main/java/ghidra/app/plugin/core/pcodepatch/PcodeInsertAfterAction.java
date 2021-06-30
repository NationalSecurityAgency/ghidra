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

import ghidra.program.model.pcode.RawPcodeImpl;
import ghidra.program.model.pcode.RawPcode;

public class PcodeInsertAfterAction extends AbstractPcodePatchAction {

    private PatchPcodeTextDialog dialog;

    public PcodeInsertAfterAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner, plugin);

        this.dialog = new PatchPcodeTextDialog(plugin, this);
    }

    @Override
    protected void showDialog() {
        this.dialog.show();
    }

    @Override
    public void doPatch(RawPcodeImpl patchPcode) {
        List<RawPcode> pcode = Stream.of(instruction.getPcode()).collect(Collectors.toList());
        pcode.add(row + 1, patchPcode);
        instruction.patchPcode(pcode.toArray(RawPcode[]::new));
    }
    
}
