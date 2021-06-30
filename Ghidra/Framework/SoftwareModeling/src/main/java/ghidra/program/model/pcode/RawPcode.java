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


/**
 * The pcode without address (or SeqNum) but only has the opcode and input/outputs.
 * 
 * Although it is quite alike, this is still not the same as {@link OpTpl} as OpTpl
 * must construct the pcode out of varnode template, which is more suitable to be used
 * in compilation context.
 * 
 * However, this is the pcode "template" that can be constructed directly as we are
 * using real varnodes instead of {@link VarnodeTpl}.
 * 
 * One of the important usecase for this is to unify the access for real pcode (i.e,
 * {@link PcodeOp}) and the {@link RawPcodeImpl} that can be constructed in the scripts.
 * 
 * Used to implement the pcode patching functionality.
 */
public interface RawPcode {
    public int getOpcode();
    public Varnode[] getInputs();
    public Varnode getOutput();
}

