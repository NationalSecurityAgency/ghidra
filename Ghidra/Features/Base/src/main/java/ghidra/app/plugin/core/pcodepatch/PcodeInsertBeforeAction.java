package ghidra.app.plugin.core.pcodepatch;

import java.util.Arrays;
import java.util.List;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

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
    public void doPatch(int opcode, Varnode[] in, Varnode out) {
        PcodeOp[] pcode = instruction.getPcode();
        SequenceNumber seqNum = pcode[row].getSeqnum();
        List<PcodeOp> pcodeAfter = Arrays.asList(pcode);
        PcodeOp inserting = new PcodeOp(seqNum, opcode, in, out);
        // reset all times after insertion
        for (int i = row; i < pcode.length; ++i) {
            pcode[i].setTime(seqNum.getTime() + i - row + 1);
        }
        pcodeAfter.add(row, inserting);
        instruction.patchPcode(pcodeAfter.toArray(PcodeOp[]::new));
    }
    
}
