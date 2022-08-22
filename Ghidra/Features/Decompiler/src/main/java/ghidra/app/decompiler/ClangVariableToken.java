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
/*
 * Created on Jun 12, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.decompiler;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

/**
 * 
 *
 * Token representing a C variable
 */
public class ClangVariableToken extends ClangToken {
	private Varnode varnode;
	private PcodeOp op;

	public ClangVariableToken(ClangNode par) {
		super(par);
		varnode = null;
		op = null;
	}

	@Override
	public Varnode getVarnode() {
		return varnode;
	}

	@Override
	public PcodeOp getPcodeOp() {
		return op;
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
		return op.getSeqnum().getTarget().getPhysicalAddress();
	}

	@Override
	public Address getMaxAddress() {
		if (op == null) {
			return null;
		}
		return op.getSeqnum().getTarget().getPhysicalAddress();
	}

	@Override
	public HighVariable getHighVariable() {
		Varnode inst = getVarnode();
		if (inst != null) {
			HighVariable hvar = inst.getHigh();
			if (hvar != null && hvar.getRepresentative() == null) {
				Varnode[] instances = new Varnode[1];
				instances[0] = inst;
				hvar.attachInstances(instances, inst);
			}
			return inst.getHigh();
		}
		return super.getHighVariable();
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == AttributeId.ATTRIB_VARREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				varnode = pfactory.getRef(refid);
			}
			else if (attribId == AttributeId.ATTRIB_OPREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				op = pfactory.getOpRef(refid);
			}
		}
		decoder.rewindAttributes();
		super.decode(decoder, pfactory);
	}
}
