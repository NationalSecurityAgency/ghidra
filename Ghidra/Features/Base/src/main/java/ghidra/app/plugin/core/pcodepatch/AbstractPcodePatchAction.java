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

import ghidra.program.model.pcode.RawPcodeImpl;

public abstract class AbstractPcodePatchAction extends AbstractPcodeManipulationAction {


    public AbstractPcodePatchAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner, plugin);
    }

    @Override
    public void initialAction() {
        showDialog();
    }

    protected abstract void showDialog();

    /**
     * Do individual action, either:
     * - patch
     * - insert before
     * - insert after
     * 
     * @param patchPcode the pcode user specifies, note that the address is temporary as
     * the user should not specify one
     */
    public abstract void doPatch(RawPcodeImpl patchPcode);
}
