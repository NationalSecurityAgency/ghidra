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
