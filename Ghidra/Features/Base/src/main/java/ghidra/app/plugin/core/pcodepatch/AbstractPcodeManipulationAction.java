package ghidra.app.plugin.core.pcodepatch;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.PcodeFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Root abstract action, parent for:
 * 
 * - pcode patch (including patch, insert before, insert after)
 * - remove patch
 * 
 * The action happens in two steps:
 * 
 * 1. initialAction(): show dialog if needed or do the job if no dialog needed
 * 2. second stage (doPatch() in subclasses): job to do after dialog returns information
 * 
 * The second stage is implemented in {@link AbstractPcodePatchAction} only which
 * implementes actions that require the second stage.
 */
public abstract class AbstractPcodeManipulationAction extends ListingContextAction {

    protected Instruction instruction;
    protected int row;

    protected PcodePatchPlugin plugin;

    public AbstractPcodeManipulationAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner);
        this.plugin = plugin;
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

        return true;
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
        PcodeFieldLocation location = (PcodeFieldLocation) context.getLocation();

        instruction = (Instruction) context.getCodeUnit();
        row = location.getRow();

        initialAction();
    }

    /**
     * Initial action, for patchings, this should show the dialog.
     * For remove, this should remove the patch.
     */
    protected abstract void initialAction();
}
