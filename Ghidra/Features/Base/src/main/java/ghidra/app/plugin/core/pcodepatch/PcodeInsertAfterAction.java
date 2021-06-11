package ghidra.app.plugin.core.pcodepatch;

import java.util.Arrays;
import java.util.List;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

public class PcodeInsertAfterAction extends AbstractPcodePatchAction {

    private PatchPcodeTextDialog dialog;

    public PcodeInsertAfterAction(String name, String owner, PcodePatchPlugin plugin) {
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
        seqNum.setTime(seqNum.getTime() + 1);

        List<PcodeOp> pcodeAfter = Arrays.asList(pcode);
        PcodeOp inserting = new PcodeOp(seqNum, opcode, in, out);

        // reset all times after insertion
        for (int i = row + 1; i < pcode.length; ++i) {
            pcode[i].setTime(seqNum.getTime() + i - row + 1);
        }
        pcodeAfter.add(row + 1, inserting);
        instruction.patchPcode(pcodeAfter.toArray(PcodeOp[]::new));
    }
    
}
