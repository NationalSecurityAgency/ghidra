package ghidra.app.plugin.core.pcodepatch;

import ghidra.program.model.pcode.Varnode;

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
     * @param pcode the pcode user specifies, note that the address is temporary as
     * the user should not specify one
     */
    public abstract void doPatch(int opcode, Varnode[] in, Varnode out);
}
