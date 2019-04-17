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
		if (op==null) return null;
		return op.getSeqnum().getTarget().getPhysicalAddress();
	}
	@Override
    public Address getMaxAddress() {
		if (op==null) return null;
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
    public void restoreFromXML(XmlElement el,XmlElement end,PcodeFactory pfactory) {
		super.restoreFromXML(el,end,pfactory);
		String varrefstring = el.getAttribute(ClangXML.VARNODEREF);
		if (varrefstring != null) {
			int refid = SpecXmlUtils.decodeInt(varrefstring);
			varnode = pfactory.getRef(refid);
		}
		String oprefstring = el.getAttribute(ClangXML.OPREF);
		if (oprefstring != null) {
			int refid = SpecXmlUtils.decodeInt(oprefstring);
			op = pfactory.getOpRef(refid);
		}
	}
}
