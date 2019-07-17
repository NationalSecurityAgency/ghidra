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
 * A "plain" goto block
 *     possible multiple incoming edges
 *     no outgoing edges
 *     1 (implied) outgoing edge representing the unstructured goto
 *
 */
public class BlockGoto extends BlockGraph {
	private PcodeBlock gototarget;
	private int gototype;			// Type of goto  (1=plaingoto 2=break 4=continue)
	
	public BlockGoto() {
		super();
		gototarget = null;
		gototype = 1;
		blocktype = PcodeBlock.GOTO;
	}
	
	public PcodeBlock getGotoTarget() {
		return gototarget;
	}
	
	public int getGotoType() {
		return gototype;
	}
	
	public void setGotoTarget(PcodeBlock gt) {
		gototarget = gt;
	}

	@Override
	public void saveXmlBody(Writer writer) throws IOException {
		super.saveXmlBody(writer);
		StringBuilder buf = new StringBuilder();
		buf.append("<target");
		PcodeBlock leaf = gototarget.getFrontLeaf();
		int depth = gototarget.calcDepth(leaf);
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "index", leaf.getIndex());
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "depth", depth);
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "type", gototype);
		buf.append("/>\n");
		writer.write(buf.toString());
	}

	@Override
	public void restoreXmlBody(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
		super.restoreXmlBody(parser, resolver);
		XmlElement el = parser.start("target");
		int target = SpecXmlUtils.decodeInt(el.getAttribute("index"));
		int depth = SpecXmlUtils.decodeInt(el.getAttribute("depth"));
		gototype = SpecXmlUtils.decodeInt(el.getAttribute("type"));
		parser.end(el);
		resolver.addGotoRef(this, target, depth);
	}
}
