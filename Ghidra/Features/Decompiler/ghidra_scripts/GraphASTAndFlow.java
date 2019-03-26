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

import ghidra.program.model.graph.GraphEdge;
import ghidra.program.model.graph.GraphVertex;
import ghidra.program.model.pcode.*;

public class GraphASTAndFlow extends GraphAST {

	@Override
	protected void buildGraph() {

		HashMap<Integer, GraphVertex> vertices = new HashMap<Integer, GraphVertex>();

		edgecount = 0;
		Iterator<PcodeOpAST> opiter = getPcodeOpIterator();
		HashMap<PcodeOp, GraphVertex> map = new HashMap<PcodeOp, GraphVertex>();
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			GraphVertex o = createOpVertex(op);
			map.put(op, o);
			for (int i = 0; i < op.getNumInputs(); ++i) {
				if ((i == 0) &&
					((op.getOpcode() == PcodeOp.LOAD) || (op.getOpcode() == PcodeOp.STORE))) {
					continue;
				}
				if ((i == 1)&&(op.getOpcode() == PcodeOp.INDIRECT))
					continue;
				VarnodeAST vn = (VarnodeAST) op.getInput(i);
				if (vn != null) {
					GraphVertex v = getVarnodeVertex(vertices, vn);
					createEdge(v, o);
				}
			}
			VarnodeAST outvn = (VarnodeAST) op.getOutput();
			if (outvn != null) {
				GraphVertex outv = getVarnodeVertex(vertices, outvn);
				if (outv != null) {
					createEdge(o, outv);
				}
			}
		}
		opiter = getPcodeOpIterator();
		HashSet<PcodeBlockBasic> seenParents = new HashSet<PcodeBlockBasic>();
		HashMap<PcodeBlock, GraphVertex> first = new HashMap<PcodeBlock, GraphVertex>();
		HashMap<PcodeBlock, GraphVertex> last = new HashMap<PcodeBlock, GraphVertex>();
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
					GraphEdge edge = createEdge(map.get(prev), map.get(next));
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
					GraphEdge edge = createEdge(last.get(in), first.get(block));
					edge.setAttribute(COLOR_ATTRIBUTE, "Red");
				}
			}
// All outs were already handled by the ins!  Don't make two links!
//			for (int i = 0; i < block.getOutSize(); i++) {
//				PcodeBlock out = block.getOut(i);
//				if (first.containsKey(out)) {
//					GraphEdge edge = createEdge(last.get(block), first.get(out));
//					edge.setAttribute(COLOR_ATTRIBUTE, "Red");
//				}
//			}
		}
	}

}
