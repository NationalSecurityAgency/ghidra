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
package ghidra.program.model.pcode;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;

import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A block representing a 2-or-more control flow branchpoint
 * 
 * possible multiple incoming edges
 * 1 or more outgoing edges (as in switch control flow)
 * 2 or more (implied) outgoing edges representing unstructured branch destinations   (switch case with goto statement)
 * 
 * 1 interior block representing the decision block of the switch
 *
 */
public class BlockMultiGoto extends BlockGraph {
	protected ArrayList<PcodeBlock> targets;
	
	public BlockMultiGoto() {
		super();
		targets = new ArrayList<PcodeBlock>();
		blocktype = PcodeBlock.MULTIGOTO;
	}
	
	public void addGotoTarget(PcodeBlock target) {
		targets.add(target);
	}
	
	@Override
	public void saveXmlBody(Writer writer) throws IOException {
		super.saveXmlBody(writer);
		for(int i=0;i<targets.size();++i) {
			
			PcodeBlock gototarget = targets.get(i);
			StringBuilder buf = new StringBuilder();
			buf.append("<target");
			PcodeBlock leaf = gototarget.getFrontLeaf();
			int depth = gototarget.calcDepth(leaf);
			SpecXmlUtils.encodeSignedIntegerAttribute(buf, "index", leaf.getIndex());
			SpecXmlUtils.encodeSignedIntegerAttribute(buf, "depth", depth);
//			SpecXmlUtils.encodeSignedIntegerAttribute(buf, "type", 2);		// Always a break
			buf.append("/>\n");
			writer.write(buf.toString());
		}
	}

	@Override
	public void restoreXmlBody(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
		super.restoreXmlBody(parser, resolver);
		while(parser.peek().isStart()) {
			XmlElement el = parser.start("target");
			int target = SpecXmlUtils.decodeInt(el.getAttribute("index"));
			int depth = SpecXmlUtils.decodeInt(el.getAttribute("depth"));
//			int gototype = SpecXmlUtils.decodeInt(el.getAttribute("type"));
			parser.end(el);
			resolver.addGotoRef(this, target, depth);
		}
	}

}
