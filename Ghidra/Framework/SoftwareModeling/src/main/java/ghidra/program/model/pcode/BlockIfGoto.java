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

import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Block representing an if () goto control flow
 * 
 * possible multiple incoming edges
 * 1 output edge if the condition is false
 * 1 (implied) output edge representing the unstructured control flow if the condition is true
 * 
 * 1 block evaluating the condition
 *
 */
public class BlockIfGoto extends BlockGraph {
	private PcodeBlock gototarget;
	private int gototype;               // type of goto 1=plaingoto 2=break 3=continue
	
	public BlockIfGoto() {
		super();
		blocktype = PcodeBlock.IFGOTO;
		gototarget = null;
		gototype = 1;
	}
	
	public void setGotoTarget(PcodeBlock bl) {
		gototarget = bl;
	}
	
	public PcodeBlock getGotoTarget() {
		return gototarget;
	}
	
	public int getGotoType() {
		return gototype;
	}

	@Override
	public void saveXmlBody(Writer writer) throws IOException {
		super.saveXmlBody(writer);
		PcodeBlock leaf = gototarget.getFrontLeaf();
		int depth = gototarget.calcDepth(leaf);
		StringBuilder buf = new StringBuilder();
		buf.append("<target");
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "index", leaf.getIndex());
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "depth", depth);
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "type", gototype);
		buf.append("/>\n");
		writer.write(buf.toString());
	}

	@Override
	public void restoreXmlBody(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
		super.restoreXmlBody(parser,resolver);
		XmlElement el = parser.start("target");
		int target = SpecXmlUtils.decodeInt(el.getAttribute("index"));
		int depth = SpecXmlUtils.decodeInt(el.getAttribute("depth"));
		gototype = SpecXmlUtils.decodeInt(el.getAttribute("type"));
		parser.end(el);
		gototarget = null;
		resolver.addGotoRef(this, target, depth);
	}
}
