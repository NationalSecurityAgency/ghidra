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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

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
	protected void encodeBody(Encoder encoder) throws IOException {
		super.encodeBody(encoder);
		encoder.openElement(ELEM_TARGET);
		PcodeBlock leaf = gototarget.getFrontLeaf();
		int depth = gototarget.calcDepth(leaf);
		encoder.writeSignedInteger(ATTRIB_INDEX, leaf.getIndex());
		encoder.writeSignedInteger(ATTRIB_DEPTH, depth);
		encoder.writeSignedInteger(ATTRIB_TYPE, gototype);
		encoder.closeElement(ELEM_TARGET);
	}

	@Override
	protected void decodeBody(Decoder decoder, BlockMap resolver) throws PcodeXMLException {
		super.decodeBody(decoder, resolver);
		int el = decoder.openElement(ELEM_TARGET);
		int target = (int) decoder.readSignedInteger(ATTRIB_INDEX);
		int depth = (int) decoder.readSignedInteger(ATTRIB_DEPTH);
		gototype = (int) decoder.readUnsignedInteger(ATTRIB_TYPE);
		decoder.closeElement(el);
		resolver.addGotoRef(this, target, depth);
	}
}
