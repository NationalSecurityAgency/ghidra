package ghidra.app.plugin.core.pcodepatch;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

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
    public void doPatch(int opcode, Varnode[] in, Varnode out) {
        PcodeOp[] pcode = instruction.getPcode();
        SequenceNumber seqNum = pcode[row].getSeqnum();

        pcode[row] = new PcodeOp(seqNum, opcode, in, out);

        instruction.patchPcode(pcode);
    }
}
