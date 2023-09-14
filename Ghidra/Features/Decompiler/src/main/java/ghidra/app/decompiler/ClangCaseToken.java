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
package ghidra.app.decompiler;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;

/**
 * A token representing a switch "case" label, or other constant not directly linked to data-flow.
 * The token has an associated constant value and a data-type
 */
public class ClangCaseToken extends ClangToken {

	private PcodeOp op;		// Op associated with the start of the "case"
	private long value;		// The constant value

	public ClangCaseToken(ClangNode par) {
		super(par);
		op = null;
		value = 0;
	}

	@Override
	public boolean isVariableRef() {
		return true;
	}

	@Override
	public Address getMinAddress() {
		if (op == null) {
			return null;
		}
		return op.getSeqnum().getTarget();
	}

	@Override
	public Address getMaxAddress() {
		if (op == null) {
			return null;
		}
		return op.getSeqnum().getTarget();
	}

	@Override
	public Varnode getVarnode() {
		PcodeOp switchOp = getSwitchOp();
		if (switchOp == null) {
			return null;
		}
		return switchOp.getInput(0);
	}

	@Override
	public PcodeOp getPcodeOp() {
		return op;
	}

	@Override
	public HighVariable getHighVariable() {
		Varnode vn = getVarnode();
		if (vn == null) {
			return null;
		}
		return vn.getHigh();
	}

	@Override
	public HighSymbol getHighSymbol(HighFunction highFunction) {
		HighVariable hvar = getHighVariable();
		if (hvar != null) {
			HighSymbol symbol = hvar.getSymbol();
			if (symbol != null) {
				return symbol;
			}
		}
		return null;
	}

	@Override
	public Scalar getScalar() {
		HighVariable hvar = getHighVariable();
		if (hvar == null) {
			return null;
		}
		DataType dt = hvar.getDataType();
		int sz = dt.getLength();
		if (sz < 1 || sz > 8) {
			return null;
		}
		boolean isSigned = true;
		if (dt instanceof AbstractIntegerDataType) {
			isSigned = ((AbstractIntegerDataType) dt).isSigned();
		}

		return new Scalar(sz * 8, value, isSigned);
	}

	/**
	 * @return the BRANCHIND PcodeOp that jumps to this label
	 */
	public PcodeOp getSwitchOp() {
		if (op == null) {
			return null;
		}
		PcodeBlockBasic parent = op.getParent();
		for (int i = 0; i < parent.getInSize(); ++i) {
			PcodeBlockBasic in = (PcodeBlockBasic) parent.getIn(i);
			PcodeOp switchOp = in.getLastOp();
			if (switchOp != null && switchOp.getOpcode() == PcodeOp.BRANCHIND) {
				return switchOp;
			}
		}
		return null;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			else if (attribId == AttributeId.ATTRIB_OPREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				op = pfactory.getOpRef(refid);
			}
			else if (attribId == AttributeId.ATTRIB_OFF.id()) {
				value = decoder.readUnsignedInteger();
			}
		}
		decoder.rewindAttributes();
		super.decode(decoder, pfactory);
	}

}
