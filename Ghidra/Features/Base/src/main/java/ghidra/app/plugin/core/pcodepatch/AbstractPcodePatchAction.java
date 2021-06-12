package ghidra.app.plugin.core.pcodepatch;

import ghidra.program.model.pcode.PcodeData;

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
    public abstract void doPatch(PcodeData patchPcode);
}
