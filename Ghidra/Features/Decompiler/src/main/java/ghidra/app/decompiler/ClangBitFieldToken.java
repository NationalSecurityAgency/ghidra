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

import static ghidra.program.model.pcode.AttributeId.*;

import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;

public class ClangBitFieldToken extends ClangToken {
	private Composite dataType;	// Structure containing the bitfield
	private int ident;			// Identifier for the bitfield within its container
	private PcodeOp op;			// The op associated with the read/write of the field

	public ClangBitFieldToken(ClangNode par) {
		super(par);
		dataType = null;
	}

	/**
	 * @return the structure datatype associated with this field token
	 */
	public DataType getDataType() {
		return dataType;
	}

	/**
	 * @return the component corresponding to the bitfield if it exists, null otherwise
	 */
	public DataTypeComponent getComponent() {
		if (ident < 0) {
			return null;
		}
		return dataType.getComponent(ident);
	}

	@Override
	public PcodeOp getPcodeOp() {
		return op;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		String datatypestring = null;
		long id = 0;
		ident = -1;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_NAME.id()) {	// Name of the structure
				datatypestring = decoder.readString();
			}
			else if (attribId == ATTRIB_ID.id()) {
				id = decoder.readUnsignedInteger();
			}
			else if (attribId == ATTRIB_OPREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				op = pfactory.getOpRef(refid);
			}
			else if (attribId == ATTRIB_OFF.id()) {
				ident = (int) decoder.readSignedInteger();
			}
		}
		if (datatypestring != null) {
			DataType dt = pfactory.getDataTypeManager().findBaseType(datatypestring, id);
			if (dt == null) {
				throw new DecoderException("Cannot find data-type in <bitfield>");
			}
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}
			if (!(dt instanceof Composite)) {
				throw new DecoderException("Data-type in <bitfield> is not a composite");
			}
			dataType = (Composite) dt;
		}
		decoder.rewindAttributes();
		super.decode(decoder, pfactory);
	}

}
