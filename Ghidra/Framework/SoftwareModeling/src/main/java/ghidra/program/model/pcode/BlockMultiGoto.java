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
import java.util.ArrayList;

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
		targets = new ArrayList<>();
		blocktype = PcodeBlock.MULTIGOTO;
	}

	public void addGotoTarget(PcodeBlock target) {
		targets.add(target);
	}

	@Override
	protected void encodeBody(Encoder encoder) throws IOException {
		super.encodeBody(encoder);
		for (PcodeBlock gototarget : targets) {
			encoder.openElement(ELEM_TARGET);
			PcodeBlock leaf = gototarget.getFrontLeaf();
			int depth = gototarget.calcDepth(leaf);
			encoder.writeSignedInteger(ATTRIB_INDEX, leaf.getIndex());
			encoder.writeSignedInteger(ATTRIB_DEPTH, depth);
//			encoder.writeSignedInteger(ATTRIB_TYPE, 2);		// Always a break
			encoder.closeElement(ELEM_TARGET);
		}
	}

	@Override
	protected void decodeBody(Decoder decoder, BlockMap resolver) throws DecoderException {
		super.decodeBody(decoder, resolver);
		for (;;) {
			int el = decoder.peekElement();
			if (el != ELEM_TARGET.id()) {
				break;
			}
			decoder.openElement();
			int target = (int) decoder.readSignedInteger(ATTRIB_INDEX);
			int depth = (int) decoder.readSignedInteger(ATTRIB_DEPTH);
			decoder.closeElement(el);
			resolver.addGotoRef(this, target, depth);
		}
	}

}
