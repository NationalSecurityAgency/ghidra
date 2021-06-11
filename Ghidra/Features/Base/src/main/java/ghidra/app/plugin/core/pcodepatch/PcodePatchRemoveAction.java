package ghidra.app.plugin.core.pcodepatch;

public class PcodePatchRemoveAction extends AbstractPcodeManipulationAction {

    public PcodePatchRemoveAction(String name, String owner, PcodePatchPlugin plugin) {
        super(name, owner, plugin);
    }

    @Override
    protected void initialAction() {
        instruction.removePatchedPcode();
    }
}
