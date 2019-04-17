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

import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

/**
 * 
 *
 * A C code token representing a function name
 * It contains a link back to the pcode function object represented by the name
 */
public class ClangFuncNameToken extends ClangToken {
	private HighFunction hfunc;	// Overall reference to function
	private PcodeOp op;				// Local reference to function op

	public ClangFuncNameToken(ClangNode par,HighFunction hf) {
		super(par);
		hfunc = hf;
		op = null;
	}
	public HighFunction getHighFunction() { return hfunc; }
	
	@Override
	public PcodeOp getPcodeOp() { return op; }
	
	@Override
    public Address getMinAddress() {
		if (op==null) return null;
		return op.getSeqnum().getTarget().getPhysicalAddress();
	}
	@Override
    public Address getMaxAddress() {
		if (op==null) return null;
		return op.getSeqnum().getTarget().getPhysicalAddress();
	}
	
	@Override
    public void restoreFromXML(XmlElement el,XmlElement end,PcodeFactory pfactory) {
		super.restoreFromXML(el,end,pfactory);
		String oprefstring = el.getAttribute(ClangXML.OPREF);
		if (oprefstring != null) {
			int refid = SpecXmlUtils.decodeInt(oprefstring);
			op = pfactory.getOpRef(refid);
		}
	}
}
