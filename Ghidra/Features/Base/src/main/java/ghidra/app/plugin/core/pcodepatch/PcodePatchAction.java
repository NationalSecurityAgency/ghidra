package ghidra.app.plugin.core.pcodepatch;

import java.util.stream.Stream;

import ghidra.program.model.pcode.PcodeData;
import ghidra.program.model.pcode.PcodeDataLike;


public class PcodePatchAction extends AbstractPcodePatchAction {

    private PatchPcodeTextDialog dialog;

    public PcodePatchAction(String name, String owner, PcodePatchPlugin plugin) {
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
        pcodes[row] = patchPcode;
        instruction.patchPcode(pcodes);
    }
}
