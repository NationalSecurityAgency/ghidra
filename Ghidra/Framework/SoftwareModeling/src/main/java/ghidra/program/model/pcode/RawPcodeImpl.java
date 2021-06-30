/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.model.pcode;

public class RawPcodeImpl implements RawPcode {

    private int opcode;
    private Varnode[] inputs;
    private Varnode output;


    /**
     * @param opcode
     * @param inputs
     * @param output
     */
    public RawPcodeImpl(int opcode, Varnode[] inputs, Varnode output) {
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
