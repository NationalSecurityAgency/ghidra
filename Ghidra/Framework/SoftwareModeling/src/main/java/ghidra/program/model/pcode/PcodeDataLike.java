package ghidra.program.model.pcode;

/**
 * Used to normalize the access of both PcodeOp and PcodeData
 */
public interface PcodeDataLike {
    public int getOpcode();
    public Varnode[] getInputs();
    public Varnode getOutput();
}

