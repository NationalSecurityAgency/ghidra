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

/**
 * A source code token representing a data-type. This does not include qualifiers on the data-type
 * like '*' (pointer to) or '[]' (array of). There should be no whitespace in the name.
 */
public class ClangTypeToken extends ClangToken {
	private DataType datatype;

	public ClangTypeToken(ClangNode par) {
		super(par);
		datatype = null;
	}

	@Override
	public boolean isVariableRef() {
		if (Parent() instanceof ClangVariableDecl) {
			return true;
		}
		return false;
	}

	/**
	 * @return the data-type associated with this token
	 */
	public DataType getDataType() {
		return datatype;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		long id = 0;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == AttributeId.ATTRIB_ID.id()) {
				id = decoder.readUnsignedInteger();
				break;
			}
		}
		decoder.rewindAttributes();
		super.decode(decoder, pfactory);
		datatype = pfactory.getDataTypeManager().findBaseType(getText(), id);
	}
}
