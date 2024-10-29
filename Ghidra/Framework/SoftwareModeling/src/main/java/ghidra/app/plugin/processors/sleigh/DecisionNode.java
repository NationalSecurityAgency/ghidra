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
 * Created on Feb 9, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.pattern.PatternBlock;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A node in the decision tree for resolving a Constructor in 
 * a SubtableSymbol based on the InstructionContext
 */
public class DecisionNode {
	private DisjointPattern[] patternlist; // patternlist and constructlist
	private Constructor[] constructlist; // go together as a pair
	private DecisionNode[] children;
//	private int num;			// Total number of patterns we distinguish
	private boolean contextdecision; // true if decision based on
	// non-instruction context
	private int startbit, bitsize; // bits in stream on which to decide
//	private DecisionNode parent;

	private List<DisjointPattern> unmodifiablePatternList;
	private List<Constructor> unmodifiableConstructorList;
	private List<DecisionNode> unmodifiableChildren;

	public List<DisjointPattern> getPatterns() {
		return unmodifiablePatternList;
	}

	public List<Constructor> getConstructors() {
		return unmodifiableConstructorList;
	}

	public List<DecisionNode> getChildren() {
		return unmodifiableChildren;
	}

	public Constructor resolve(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException, UnknownInstructionException {
		if (bitsize == 0) { // The node is terminal
			for (int i = 0; i < patternlist.length; ++i) {
				if (debug != null) {
					debug.append("check pattern[" + (i + 1) + " of " + patternlist.length + "]");
					debug.dumpConstructor(walker.getCurrentSubtableName(), constructlist[i]);
					debug.indent();
				}
				boolean match = patternlist[i].isMatch(walker, debug);
				if (debug != null) {
					debug.dropIndent();
				}
				if (match) {
					return constructlist[i];
				}
			}
			if (debug != null) {
				debug.append("Unable to resolve constructor\n");
			}
			throw new UnknownInstructionException(
				"Unable to resolve constructor at " + walker.getAddr());
		}
		int val;
		if (contextdecision) {
			val = walker.getContextBits(startbit, bitsize);
			debugContextBitsDecision(debug, walker, val);
		}
		else {
			val = walker.getInstructionBits(startbit, bitsize);
			debugInstructionBitsDecision(debug, walker, val);
		}

		Constructor c = children[val].resolve(walker, debug);
		return c;
	}

	private void debugContextBitsDecision(SleighDebugLogger debug, ParserWalker walker, int val) {
		if (debug == null || !debug.isVerboseEnabled()) {
			return;
		}
		debug.append("decide on context bits: bitrange=(" + startbit + "," +
			(startbit + bitsize - 1) + "), value=0x" + Integer.toHexString(val) + ", context=");
		debug.append(walker.getParserContext().getContextBytes(), startbit, bitsize);
		debug.append("\n");
		debugDumpDescendantConstructors(debug, children[val]);
	}

	private void debugInstructionBitsDecision(SleighDebugLogger debug, ParserWalker walker,
			int val) {
		if (debug == null) {
			return;
		}

		int offset = walker.getOffset(-1);
		int mask = (-1 << (32 - bitsize)) >>> startbit;
		debug.addInstructionPattern(offset, new PatternBlock(0, mask, val));

		if (!debug.isVerboseEnabled()) {
			return;
		}

		MemBuffer memBuf = walker.getParserContext().getMemBuffer();
		int unitSize = memBuf.getAddress().getAddressSpace().getAddressableUnitSize();
		int byteCnt = offset + ((startbit + bitsize + 7) / 8);
		int wordCnt = (byteCnt + unitSize - 1) / unitSize;
		byte[] bytes = new byte[wordCnt * unitSize];
		memBuf.getBytes(bytes, 0);
		debug.append(
			"decide on instruction bits: byte-offset=" + offset + ", bitrange=(" + startbit + "," +
				(startbit + bitsize - 1) + "), value=0x" + Integer.toHexString(val) + ", bytes=");
		debug.append(bytes, (offset * 8) + startbit, bitsize);
		debug.append("\n");
		debugDumpDescendantConstructors(debug, children[val]);
	}

	private void debugDumpDescendantConstructors(SleighDebugLogger debug, DecisionNode child) {
		debug.indent();
		debug.append(
			"descendant constructors for decision node (complete tree dump ordered by line number):\n");
		List<Constructor> clist = new ArrayList<>();
		child.dumpDescendantConstructors(clist);
		for (Constructor c : clist) {
			debug.dumpConstructor(null, c);
		}
		debug.dropIndent();
	}

	private static final Comparator<Constructor> debugInstructionComparator =
		new Comparator<Constructor>() {
			@Override
			public int compare(Constructor c1, Constructor c2) {
				return c1.getLineno() - c2.getLineno();
			}
		};

	private void dumpDescendantConstructors(List<Constructor> clist) {
		if (bitsize == 0) { // The node is terminal
			for (Constructor c : constructlist) {
				int index = Collections.binarySearch(clist, c, debugInstructionComparator);
				if (index >= 0) {
					continue; // skip
				}
				index = -index - 1;
				clist.add(index, c);
			}
		}
		else {
			for (DecisionNode child : children) {
				child.dumpDescendantConstructors(clist);
			}
		}
	}

//	/**
//   * NOTE! Do not delete this method even if commented-out!
//	 * Test method to discover where a particular mnemonic constructor exists.
//	 * within the parse tree.
//   * This method relies on TestEnv which is inappropriate for a production core class. 
//	 * @param node 
//	 * @param name
//	 * @param path
//	 */
//	public static void findConstructorPath(DecisionNode node, String name, int[] path) {
//		if (node.children.length != 0) {
//			int[] nextPath;
//			int pathIndex = 0;
//			if (path == null) {
//				nextPath = new int[1];
//			}
//			else {
//				pathIndex = path.length;
//				nextPath = new int[path.length+1];
//				System.arraycopy(path, 0, nextPath, 0, path.length);
//			}
//			for (int i = 0; i < node.children.length; i++) {
//				nextPath[pathIndex] = i;
//				findConstructorPath(node.children[i], name, nextPath);
//			}
//		}
//		else {
//			for (int j = 0; j < node.constructlist.length; j++) {
//				Constructor c = node.constructlist[j];
//				String[] pps = (String[])TestEnv.getInstanceField("printpiece", c);
//				if (pps.length != 0 && pps[0].startsWith(name)) {
//					StringBuffer sb = new StringBuffer();
//					for (int p : path) {
//						sb.append(Integer.toString(p));
//						sb.append('.');
//					}
//					sb.append(Integer.toString(j));
//					System.out.println(sb.toString());
//				}
//			}
//		}
//	}

	public void decode(Decoder decoder, DecisionNode par, SubtableSymbol sub)
			throws DecoderException {
		int el = decoder.openElement(ELEM_DECISION);

		contextdecision = decoder.readBool(ATTRIB_CONTEXT);
		startbit = (int) decoder.readSignedInteger(ATTRIB_STARTBIT);
		bitsize = (int) decoder.readSignedInteger(ATTRIB_SIZE);

		ArrayList<Object> patlist = new ArrayList<>();
		ArrayList<Object> conlist = new ArrayList<>();
		ArrayList<Object> childlist = new ArrayList<>();
//		num = 0;
		int subel = decoder.peekElement();
		while (subel != 0) {
			if (subel == ELEM_PAIR.id()) {
				decoder.openElement();
				int id = (int) decoder.readSignedInteger(ATTRIB_ID);
				conlist.add(sub.getConstructor(id));
				patlist.add(DisjointPattern.decodeDisjoint(decoder));
				decoder.closeElement(subel);
			}
			else if (subel == ELEM_DECISION.id()) {
				DecisionNode subnode = new DecisionNode();
				subnode.decode(decoder, this, sub);
				childlist.add(subnode);
			}
			subel = decoder.peekElement();
		}
		patternlist = new DisjointPattern[patlist.size()];
		patlist.toArray(patternlist);
		constructlist = new Constructor[conlist.size()];
		conlist.toArray(constructlist);
		children = new DecisionNode[childlist.size()];
		childlist.toArray(children);
		decoder.closeElement(el);

		unmodifiablePatternList = Collections.unmodifiableList(Arrays.asList(patternlist));
		unmodifiableConstructorList = Collections.unmodifiableList(Arrays.asList(constructlist));
		unmodifiableChildren = Collections.unmodifiableList(Arrays.asList(children));
	}
}
