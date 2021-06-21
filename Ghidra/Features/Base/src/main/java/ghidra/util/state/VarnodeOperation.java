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
package ghidra.util.state;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class VarnodeOperation extends Varnode {

	private final PcodeOp pcodeOp;
	private final Varnode[] inputValues;
	private boolean simplified;

	public VarnodeOperation(PcodeOp pcodeOp, Varnode[] inputValues) {
		super(pcodeOp.getSeqnum().getTarget(), getSize(pcodeOp));
		this.pcodeOp = pcodeOp;
		this.inputValues = inputValues;
	}

	private static int getSize(PcodeOp op) {
		Varnode v = op.getOutput();
		return v != null ? v.getSize() : 0;
	}

	public boolean isSimplified() {
		return simplified;
	}

	public void setSimplified(boolean simplified) {
		this.simplified = simplified;
	}

	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		}
		if (!(o instanceof VarnodeOperation)) {
			return false;
		}
		VarnodeOperation other = (VarnodeOperation) o;
		if (pcodeOp.getOpcode() != other.pcodeOp.getOpcode()) {
			return false;
		}
		for (int i = 0; i < inputValues.length; i++) {
			if (!inputValues[i].equals(other.inputValues[i])) {
				return false;
			}
		}
		return true;
	}

	@Override
	public int hashCode() {
		return pcodeOp.getSeqnum().hashCode();
	}

	public PcodeOp getPCodeOp() {
		return pcodeOp;
	}

	public Varnode[] getInputValues() {
		return inputValues;
	}

	private String getIndirectString(Language language) {
		Varnode output = pcodeOp.getOutput();
		if (language == null) {
			return pcodeOp.getMnemonic() + "[" + output.toString() + ", @" +
				pcodeOp.getSeqnum().getTarget() + "]";
		}
		return pcodeOp.getMnemonic() + "[" + output.toString(language) + ", @" +
			pcodeOp.getSeqnum().getTarget() + "]";
	}

	@Override
	public String toString() {
		if (pcodeOp.getOpcode() == PcodeOp.INDIRECT) {
			return getIndirectString(null);
		}
		String s = pcodeOp.getMnemonic() + " ";
		for (int i = 0; i < inputValues.length; i++) {
			if (inputValues[i] == null) {
				s += "null";
			}
			else if (inputValues[i] instanceof VarnodeOperation) {
				s += "{" + inputValues[i].toString() + "}";
			}
			else {
				s += inputValues[i].toString();
			}
			if (i < inputValues.length - 1) {
				s += ", ";
			}
		}
		return s;
	}

	@Override
	public String toString(Language language) {
		if (pcodeOp.getOpcode() == PcodeOp.INDIRECT) {
			return getIndirectString(language);
		}
		String s = pcodeOp.getMnemonic() + " ";
		for (int i = 0; i < inputValues.length; i++) {
			if (i == 0 &&
				(pcodeOp.getOpcode() == PcodeOp.LOAD || pcodeOp.getOpcode() == PcodeOp.STORE)) {
				AddressSpace space =
					language.getAddressFactory().getAddressSpace((int) inputValues[0].getOffset());
				if (space != null) {
					s += "[" + space.getName() + "], ";
					continue;
				}
			}
			if (inputValues[i] == null) {
				s += "null";
			}
			else if (inputValues[i] instanceof VarnodeOperation) {
				s += "{" + inputValues[i].toString(language) + "}";
			}
			else {
				s += inputValues[i].toString(language);
			}
			if (i < inputValues.length - 1) {
				s += ", ";
			}
		}
		return s;
	}

	@Override
	public boolean isAddress() {
		return false;
	}

	@Override
	public boolean isAddrTied() {
		return false;
	}

	@Override
	public boolean isConstant() {
		return false;
	}

	@Override
	public boolean isFree() {
		return false;
	}

	@Override
	public boolean isInput() {
		return false;
	}

	@Override
	public boolean isPersistent() {
		return false;
	}

	@Override
	public boolean isRegister() {
		return false;
	}

	@Override
	public boolean isUnaffected() {
		return false;
	}

	@Override
	public boolean isUnique() {
		return false;
	}

	@Override
	public void trim() {
	}

}
