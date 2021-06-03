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
//Decompile the function at the cursor, then build data-flow graph (AST) with flow edges
//@category PCode

import java.util.*;

import ghidra.program.model.pcode.*;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

public class GraphASTAndFlow extends GraphAST {

	@Override
	protected void buildGraph() {

		HashMap<Integer, AttributedVertex> vertices = new HashMap<>();

		Iterator<PcodeOpAST> opiter = getPcodeOpIterator();
		HashMap<PcodeOp, AttributedVertex> map = new HashMap<PcodeOp, AttributedVertex>();
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			AttributedVertex o = createOpVertex(op);
			map.put(op, o);
			for (int i = 0; i < op.getNumInputs(); ++i) {
				if ((i == 0) &&
					((op.getOpcode() == PcodeOp.LOAD) || (op.getOpcode() == PcodeOp.STORE))) {
					continue;
				}
				if ((i == 1) && (op.getOpcode() == PcodeOp.INDIRECT)) {
					continue;
				}
				VarnodeAST vn = (VarnodeAST) op.getInput(i);
				if (vn != null) {
					AttributedVertex v = getVarnodeVertex(vertices, vn);
					createEdge(v, o);
				}
			}
			VarnodeAST outvn = (VarnodeAST) op.getOutput();
			if (outvn != null) {
				AttributedVertex outv = getVarnodeVertex(vertices, outvn);
				if (outv != null) {
					createEdge(o, outv);
				}
			}
		}
		opiter = getPcodeOpIterator();
		HashSet<PcodeBlockBasic> seenParents = new HashSet<PcodeBlockBasic>();
		HashMap<PcodeBlock, AttributedVertex> first = new HashMap<>();
		HashMap<PcodeBlock, AttributedVertex> last = new HashMap<>();
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			PcodeBlockBasic parent = op.getParent();
			if (seenParents.contains(parent)) {
				continue;
			}
			Iterator<PcodeOp> iterator = parent.getIterator();
			PcodeOp prev = null;
			PcodeOp next = null;
			while (iterator.hasNext()) {
				next = iterator.next();
				if (prev == null && map.containsKey(next)) {
					first.put(parent, map.get(next));
				}
				if (prev != null && map.containsKey(prev) && map.containsKey(next)) {
					AttributedEdge edge = createEdge(map.get(prev), map.get(next));
					edge.setAttribute(COLOR_ATTRIBUTE, "Black");
				}
				prev = next;
			}
			if (next != null && map.containsKey(next)) {
				last.put(parent, map.get(next));
			}
			seenParents.add(parent);
		}
		Set<PcodeBlock> keySet = first.keySet();
		for (PcodeBlock block : keySet) {
			for (int i = 0; i < block.getInSize(); i++) {
				PcodeBlock in = block.getIn(i);
				if (last.containsKey(in)) {
					AttributedEdge edge = createEdge(last.get(in), first.get(block));
					edge.setAttribute(COLOR_ATTRIBUTE, "Red");
				}
			}
		}
	}

}
