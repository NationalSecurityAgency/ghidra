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

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;

/**
 * A grouping of source code tokens representing the "return type" of a function,
 * as at the beginning of a function prototype.
 */
public class ClangReturnType extends ClangTokenGroup {
	private DataType datatype;
	private Varnode varnode;

	public ClangReturnType(ClangNode par) {
		super(par);
		varnode = null;
		datatype = null;
	}

	/**
	 * @return the data-type represented by this text
	 */
	public DataType getDataType() {
		return datatype;
	}

	/**
	 * @return a Varnode representing the return value in the function's data-flow
	 */
	public Varnode getVarnode() {
		return varnode;
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
				if (varnode != null) {
					if (varnode.getHigh() == null) {
						Msg.warn(this, "VOID high variable problem at " + varnode.getAddress());
						return;
					}
					datatype = varnode.getHigh().getDataType();
				}
				break;
			}
		}
		super.decode(decoder, pfactory);
	}
}
