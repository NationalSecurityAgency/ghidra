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
 * A grouping of source code tokens representing a variable declaration.
 * This can be for a one line declaration (as for local variables) or
 * as part of a function prototype declaring a parameter.
 */
public class ClangVariableDecl extends ClangTokenGroup {
	private DataType datatype;
	private HighSymbol symbol;

	public ClangVariableDecl(ClangNode par) {
		super(par);
		datatype = null;
		symbol = null;
	}

	/**
	 * @return the data-type of the variable being declared
	 */
	public DataType getDataType() {
		return datatype;
	}

	/**
	 * @return the HighVariable (collection of Varnodes) associated with the variable
	 */
	public HighVariable getHighVariable() {
		if (symbol != null) {
			return symbol.getHighVariable();
		}
		return null;
	}

	/**
	 * @return the symbol defined by this variable declaration
	 */
	public HighSymbol getHighSymbol() {
		return symbol;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		long symref = decoder.readUnsignedInteger(AttributeId.ATTRIB_SYMREF);
		super.decode(decoder, pfactory);
		symbol = pfactory.getSymbol(symref);
		if (symbol == null) {
			Msg.error(this, "Invalid symbol reference: " + symref + " in " + Parent());
			return;
		}
		datatype = symbol.getDataType();
	}
}
