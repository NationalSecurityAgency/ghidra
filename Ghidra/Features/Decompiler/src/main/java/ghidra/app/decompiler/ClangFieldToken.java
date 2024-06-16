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

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;

/**
 * A source code token representing a structure field.
 */
public class ClangFieldToken extends ClangToken {
	private DataType datatype;			// Structure from which this field is a part
	private int offset;					// Byte offset of the field within the structure
	private PcodeOp op;					// The op associated with the field extraction

	public ClangFieldToken(ClangNode par) {
		super(par);
		datatype = null;
	}

	/**
	 * @return the structure datatype associated with this field token
	 */
	public DataType getDataType() {
		return datatype;
	}

	/**
	 * @return the byte offset of this field with its structure
	 */
	public int getOffset() {
		return offset;
	}

	@Override
	public PcodeOp getPcodeOp() {
		return op;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		String datatypestring = null;
		long id = 0;
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
			else if (attribId == ATTRIB_OFF.id()) {
				offset = (int) decoder.readSignedInteger();
			}
			else if (attribId == ATTRIB_OPREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				op = pfactory.getOpRef(refid);
			}
		}
		if (datatypestring != null) {
			datatype = pfactory.getDataTypeManager().findBaseType(datatypestring, id);
		}
		decoder.rewindAttributes();
		super.decode(decoder, pfactory);
	}

}
