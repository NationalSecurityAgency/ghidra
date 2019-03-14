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
package ghidra.app.decompiler;

import ghidra.program.model.pcode.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

public class ClangBreak extends ClangToken {
	
	private int indent;		// Number of characters of indent
	
	public ClangBreak(ClangNode par) {
		super(par);
		indent = 0;
	}
	
	public ClangBreak(ClangNode par,int indent) {
		super(par);
		this.indent = indent;
	}
	
	public int getIndent() { return indent; }
	
	@Override
    public void restoreFromXML(XmlElement el,XmlElement end,PcodeFactory pfactory) {
		super.restoreFromXML(el,end,pfactory);
		indent = SpecXmlUtils.decodeInt(el.getAttribute("indent"));
	}
}
