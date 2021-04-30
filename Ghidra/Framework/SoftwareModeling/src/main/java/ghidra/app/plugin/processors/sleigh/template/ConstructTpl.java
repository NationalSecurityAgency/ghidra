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
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.template;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.util.ArrayList;

/**
 * 
 *
 * Placeholder for what resolves to a list of PcodeOps and
 * a FixedHandle. It represents the semantic action of a constructor
 * and its return value for a particular InstructionContext
 */

public class ConstructTpl {

	private int numlabels=0;
	private OpTpl[] vec;				// The semantic action of constructor
	private HandleTpl result;			// The final semantic value
	
	public ConstructTpl() {
	}
	
	public int getNumLabels() { return numlabels; }
	public OpTpl[] getOpVec() { return vec; }
	public HandleTpl getResult() { return result; }
	
	public int restoreXml(XmlPullParser parser,AddressFactory factory) throws UnknownInstructionException {
		int sectionid = -1;
	    XmlElement el = parser.start("construct_tpl");
//		String delaystr = el.getAttribute("delay");
//		if (delaystr != null)
//			delayslot = SpecXmlUtils.decodeInt(delaystr);
		String nmlabelstr = el.getAttribute("labels");
		if (nmlabelstr != null)
			numlabels = SpecXmlUtils.decodeInt(nmlabelstr);
		String sectionidstr = el.getAttribute("section");
		if (sectionidstr != null)
			sectionid = SpecXmlUtils.decodeInt(sectionidstr);
		XmlElement handel = parser.peek();
		if (handel.getName().equals("null")) {
			result = null;
			parser.discardSubTree();
		}
		else {
			result = new HandleTpl();
			result.restoreXml(parser,factory);
		}
		ArrayList<Object> oplist = new ArrayList<Object>();
		while(!parser.peek().isEnd()) {
			OpTpl op = new OpTpl();
			op.restoreXml(parser,factory);
			oplist.add(op);
		}
		vec = new OpTpl[oplist.size()];
		oplist.toArray(vec);
		parser.end(el);
		return sectionid;
	}
	
}
