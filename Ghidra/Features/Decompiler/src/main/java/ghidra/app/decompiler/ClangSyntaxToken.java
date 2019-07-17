/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.pcode.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

/**
 * 
 *
 * A C code token which is not an operation, variable, function name, or type. Like '(' or ','
 * A SyntaxToken may be or may include spacing
 */
public class ClangSyntaxToken extends ClangToken {
	private int open,close;
	public ClangSyntaxToken(ClangNode par) {
		super(par);
		open = close = -1;
	}
	public ClangSyntaxToken(ClangNode par,String txt) {
		super(par,txt);
		open = close = -1;
	}
	public ClangSyntaxToken(ClangNode par,String txt,String col) {
		super(par,txt,col);
		open = close = -1;
	}
	
	@Override
    public boolean isVariableRef() {
		if (Parent() instanceof ClangVariableDecl) return true;
		return false;	
	}
	
	@Override
    public void restoreFromXML(XmlElement el,XmlElement end,PcodeFactory pfactory) {
		super.restoreFromXML(el,end,pfactory);
		String str = el.getAttribute("open");
		if (str != null)
			open = SpecXmlUtils.decodeInt(str);
		str = el.getAttribute("close");
		if (str != null)
			close = SpecXmlUtils.decodeInt(str);
	}
	
	public int getOpen() { return open; }
	public int getClose() { return close; }
}
 
