package ghidra.program.model.pcode;

public class PcodeData implements PcodeDataLike {

    private int opcode;
    private Varnode[] inputs;
    private Varnode output;


    /**
     * @param opcode
     * @param inputs
     * @param output
     */
    public PcodeData(int opcode, Varnode[] inputs, Varnode output) {
        this.opcode = opcode;
        this.inputs = inputs;
        this.output = output;
    }
    /**
     * @return the opcode
     */
    public int getOpcode() {
        return opcode;
    }
    /**
     * @param opcode the opcode to set
     */
    public void setOpcode(int opcode) {
        this.opcode = opcode;
    }
    /**
     * @return the inputs
     */
    public Varnode[] getInputs() {
        return inputs;
    }
    /**
     * @param inputs the inputs to set
     */
    public void setInputs(Varnode[] inputs) {
        this.inputs = inputs;
    }
    /**
     * @return the output
     */
    public Varnode getOutput() {
        return output;
    }
    /**
     * @param output the output to set
     */
    public void setOutput(Varnode output) {
        this.output = output;
    }

    
}
