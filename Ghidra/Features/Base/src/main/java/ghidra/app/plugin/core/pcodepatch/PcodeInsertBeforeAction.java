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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import ghidra.program.model.pcode.PcodeData;
import ghidra.program.model.pcode.PcodeDataLike;

public class PcodeInsertBeforeAction extends AbstractPcodePatchAction {

    private PatchPcodeTextDialog dialog;

    public PcodeInsertBeforeAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner, plugin);

        this.dialog = new PatchPcodeTextDialog(plugin, this);
    }

    @Override
    protected void showDialog() {
        this.dialog.show();
    }

    @Override
    public void doPatch(PcodeData patchPcode) {
        PcodeDataLike[] pcodes = Stream.of(instruction.getPcode()).toArray(PcodeDataLike[]::new);
        List<PcodeDataLike> pcodeAfter = Arrays.asList(pcodes);
        pcodeAfter.add(row, patchPcode);
        instruction.patchPcode(pcodeAfter.toArray(PcodeDataLike[]::new));
    }
    
}
