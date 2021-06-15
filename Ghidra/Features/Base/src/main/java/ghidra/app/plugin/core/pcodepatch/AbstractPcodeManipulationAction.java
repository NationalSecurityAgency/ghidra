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
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.PcodeFieldLocation;
import ghidra.program.util.ProgramLocation;

public abstract class AbstractPcodeManipulationAction extends ListingContextAction {

    protected Instruction instruction;
    protected int row;

    protected PcodePatchPlugin plugin;

    public AbstractPcodeManipulationAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner);
        this.plugin = plugin;
    }

    private void initFromContext(ListingActionContext context) {
        PcodeFieldLocation location = (PcodeFieldLocation) context.getLocation();
        instruction = (Instruction) context.getCodeUnit();
        row = location.getRow();
    }

    @Override
    protected boolean isEnabledForContext(ListingActionContext context) {
        if (!(context instanceof ListingActionContext)) {
            return false;
        }

        ListingActionContext listingActionContext = (ListingActionContext) context;

        Program program = listingActionContext.getProgram();
        if (program == null) {
            return false;
        }

        ProgramLocation location = listingActionContext.getLocation();
        Address addr = location.getAddress();

        MemoryBlock block = program.getMemory().getBlock(addr);
        if (block == null || !block.isInitialized()) {
            return false;
        }

        if (!(location instanceof PcodeFieldLocation)) {
            return false;
        }

        CodeUnit cu = listingActionContext.getCodeUnit();

        if (!(cu instanceof Instruction)) {
            return false;
        }

        initFromContext(context);

        return true;
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
        initFromContext(context);
        initialAction();
    }

    /**
     * Initial action, for patchings, this should show the dialog.
     * For remove, this should remove the patch.
     */
    protected abstract void initialAction();
}
