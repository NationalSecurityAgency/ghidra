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
package ghidra.app.plugin.core.instructionsearch.model;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;

/**
 * Data container encapsulating all pertinent mask information about a single
 * instruction. In some cases, the user may have selected a set of instructions
 * that contains data elements that are technically NOT instructions, but are
 * captured using this data structure anyway (hence the private 'instruction'
 * boolean.
 */
public class InstructionMetadata {

	private Address addr;
	private String mnemonic;

	// Indicates if this is a 'real' instruction or a data element.  
	private boolean isInstruction;

	// Indicates if the mnemonic is masked (true) or not (false).
	private boolean mnemonicMasked = false;

	// The byte arrays describing the current mask.
	private MaskContainer maskContainer;

	// List of all operands in this instruction.
	private List<OperandMetadata> operands = new ArrayList<>();

	/**
	 * Constructor. We always need to have a mask container, so force users to
	 * pass it in.
	 * 
	 * @param maskContainer
	 */
	public InstructionMetadata(MaskContainer maskContainer) {
		this.maskContainer = maskContainer;
	}

	public MaskContainer getMaskContainer() {
		return maskContainer;
	}

	public Address getAddr() {
		return addr;
	}

	public void setAddr(Address addr) {
		this.addr = addr;
	}

	public String getTextRep() {
		return mnemonic;
	}

	public void setTextRep(String textRep) {
		this.mnemonic = textRep;
	}

	public boolean isInstruction() {
		return isInstruction;
	}

	public void setIsInstruction(boolean instruction) {
		this.isInstruction = instruction;
	}

	public List<OperandMetadata> getOperands() {
		return operands;
	}

	public void setOperands(List<OperandMetadata> operands) {
		this.operands = operands;
	}

	public boolean isMasked() {
		return mnemonicMasked;
	}

	public void setMasked(boolean mask) {
		this.mnemonicMasked = mask;
	}

}
