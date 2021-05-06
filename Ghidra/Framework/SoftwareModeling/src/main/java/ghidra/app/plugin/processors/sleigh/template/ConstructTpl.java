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
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.template;

import java.util.ArrayList;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A constructor template, representing the semantic action of a SLEIGH constructor, without
 * its final context.  The constructor template is made up of a list of p-code op templates,
 * which are in turn made up of varnode templates.
 * This is one step removed from the final array of PcodeOp objects, but:
 *   - Constants may still need to incorporate context dependent address resolution and relative offsets.
 *   - Certain p-code operations may still need expansion to include a dynamic LOAD or STORE operation.
 *   - The list may hold "build" directives for sub-constructor templates.
 *   - The list may still hold "label" information for the final resolution of relative jump offsets.
 * 
 * The final PcodeOps are produced by handing this to the build() method of PcodeEmit which has
 * the InstructionContext necessary for final resolution.
 */

public class ConstructTpl {

	private int numlabels = 0;			// Number of relative-offset labels in this template
	private OpTpl[] vec;				// The semantic action of constructor
	private HandleTpl result;			// The final semantic value

	/**
	 * Constructor for use with restoreXML
	 */
	public ConstructTpl() {
	}

	/**
	 * Manually build a constructor template. This is useful for building constructor templates
	 * outside of the normal SLEIGH pipeline, as for an internally created InjectPayload.
	 * @param opvec is the list of p-code op templates making up the constructor
	 */
	public ConstructTpl(OpTpl[] opvec) {
		vec = opvec;
		result = null;
	}

	/**
	 * @return the number of labels needing resolution in this template
	 */
	public int getNumLabels() {
		return numlabels;
	}

	/**
	 * @return the list of p-code op templates making up this constructor template
	 */
	public OpTpl[] getOpVec() {
		return vec;
	}

	/**
	 * @return the (possibly dynamic) location of the final semantic value produced by this constructor
	 */
	public HandleTpl getResult() {
		return result;
	}

	/**
	 * Restore this template from a \<construct_tpl> tag in an XML stream.
	 * @param parser is the XML stream
	 * @param factory is for manufacturing Address objects
	 * @return the constructor section id described by the tag
	 * @throws UnknownInstructionException if the p-code templates contain unknown op-codes
	 */
	public int restoreXml(XmlPullParser parser, AddressFactory factory)
			throws UnknownInstructionException {
		int sectionid = -1;
		XmlElement el = parser.start("construct_tpl");
		String nmlabelstr = el.getAttribute("labels");
		if (nmlabelstr != null) {
			numlabels = SpecXmlUtils.decodeInt(nmlabelstr);
		}
		String sectionidstr = el.getAttribute("section");
		if (sectionidstr != null) {
			sectionid = SpecXmlUtils.decodeInt(sectionidstr);
		}
		XmlElement handel = parser.peek();
		if (handel.getName().equals("null")) {
			result = null;
			parser.discardSubTree();
		}
		else {
			result = new HandleTpl();
			result.restoreXml(parser, factory);
		}
		ArrayList<Object> oplist = new ArrayList<>();
		while (!parser.peek().isEnd()) {
			OpTpl op = new OpTpl();
			op.restoreXml(parser, factory);
			oplist.add(op);
		}
		vec = new OpTpl[oplist.size()];
		oplist.toArray(vec);
		parser.end(el);
		return sectionid;
	}

}
