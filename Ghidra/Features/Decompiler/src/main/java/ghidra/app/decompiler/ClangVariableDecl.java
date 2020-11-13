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

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A group of C code tokens forming a variable declaration.
 * This can be for a one line declaration (as for local variables) or
 * as part of a function prototype declaring a parameter
 */
public class ClangVariableDecl extends ClangTokenGroup {
	private DataType datatype;
	private HighVariable typevar;

	public ClangVariableDecl(ClangNode par) {
		super(par);
		datatype = null;
		typevar = null;
	}

	public DataType getDataType() {
		return datatype;
	}

	public HighVariable getHighVariable() {
		return typevar;
	}

	@Override
	public void restoreFromXML(XmlPullParser parser, PcodeFactory pfactory) {
		XmlElement node = parser.peek();
		super.restoreFromXML(parser, pfactory);
		long symref = SpecXmlUtils.decodeLong(node.getAttribute(ClangXML.SYMREF));
		HighSymbol sym = pfactory.getSymbol(symref);
		if (sym == null) {
			Msg.error(this, "Invalid symbol reference: " + symref + " in " + Parent());
			return;
		}
		typevar = sym.getHighVariable();
		datatype = sym.getDataType();
	}
}
