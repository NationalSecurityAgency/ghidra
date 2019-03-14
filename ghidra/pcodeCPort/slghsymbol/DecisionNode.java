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
package ghidra.pcodeCPort.slghsymbol;

import java.io.PrintStream;
import java.util.Iterator;
import java.util.List;

import org.jdom.Element;

import generic.stl.*;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.slghpattern.DisjointPattern;
import ghidra.pcodeCPort.translate.BadDataError;
import ghidra.pcodeCPort.utils.XmlUtils;

public class DecisionNode {

	private VectorSTL<Pair<DisjointPattern, Constructor>> list =
		new VectorSTL<>();
	private VectorSTL<DecisionNode> children = new VectorSTL<>();
	private int num; // Total number of patterns we distinguish
	private boolean contextdecision; // True if this is decision based on context
	private int startbit, bitsize; // Bits in the stream on which to base the decision
	private DecisionNode parent;

	public DecisionNode() {
	} // For use with restoreXml

	public DecisionNode(DecisionNode p) {
		parent = p;
		num = 0;
		startbit = 0;
		bitsize = 0;
		contextdecision = false;
	}

	// We own sub nodes
	public void dispose() {
		IteratorSTL<DecisionNode> iter;
		for (iter = children.begin(); !iter.isEnd(); iter.increment()) {
			iter.get().dispose();
		}
		IteratorSTL<Pair<DisjointPattern, Constructor>> piter;
		for (piter = list.begin(); !piter.isEnd(); piter.increment()) {
			piter.get().first.dispose(); // Delete the patterns
		}
	}

	public void addConstructorPair(DisjointPattern pat, Constructor ct) {
		DisjointPattern clone = (DisjointPattern) pat.simplifyClone(); // We need to own pattern
		list.push_back(new Pair<>(clone, ct));
		num += 1;
	}

	// Get maximum length of instruction pattern in bytes
	private int getMaximumLength(boolean context) {
		int max = 0;
		int val, i;

		for (i = 0; i < list.size(); ++i) {
			val = list.get(i).first.getLength(context);
			if (val > max) {
				max = val;
			}
		}
		return max;
	}

	private int getNumFixed(int low, int size, boolean context)

	{ // Get number of patterns that specify this field
		int count = 0;
		long mask;
		// Bits which must be specified in the mask
		long m = (size == 8 * 8) ? 0 : (((long) 1) << size);
		m = m - 1;

		for (int i = 0; i < list.size(); ++i) {
			mask = list.get(i).first.getMask(low, size, context);
			if ((mask & m) == m) {
				count += 1;
			}
		}
		return count;
	}

	private double getScore(int low, int size, boolean context) {
		int numBins = 1 << size;
		int i;
		int val;
		long mask;
		long m = (size == 8 * 8) ? 0 : (((long) 1) << size);
		m = m - 1;

		int total = 0;
		int[] count = new int[numBins];

		for (i = 0; i < list.size(); ++i) {
			mask = list.get(i).first.getMask(low, size, context);
			if ((mask & m) != m) {
				continue; // Skip if field not fully specified
			}
			val = list.get(i).first.getValue(low, size, context);
			total += 1;
			count[val] += 1;
		}
		if (total <= 0) {
			return -1.0;
		}
		double sc = 0.0;
		for (i = 0; i < numBins; ++i) {
			if (count[i] <= 0) {
				continue;
			}
			if (count[i] >= list.size()) {
				return -1.0;
			}
			double p = ((double) count[i]) / total;
			sc -= p * Math.log(p);
		}
		return (sc / Math.log(2.0));
	}

	private void chooseOptimalField() {
		double score = 0.0;
		int sbit, size; // The current field
		boolean context;
		double sc;

		int maxlength, numfixed, maxfixed;

		maxfixed = 1;
		context = true;
		do {
			maxlength = 8 * getMaximumLength(context);
			for (sbit = 0; sbit < maxlength; ++sbit) {
				numfixed = getNumFixed(sbit, 1, context); // How may patterns specify this bit
				if (numfixed < maxfixed) {
					continue; // Skip this bit, if we don't have maximum specification
				}
				sc = getScore(sbit, 1, context);

				// if we got more patterns this time than previously, and a positive score, reset
				// the high score (we prefer this bit, because it has a higher numfixed, regardless
				// of the difference in score, as long as the new score is positive).
				if ((numfixed > maxfixed) && (sc > 0.0)) {
					score = sc;
					maxfixed = numfixed;
					startbit = sbit;
					bitsize = 1;
					contextdecision = context;
					continue;
				}
				// We have maximum patterns
				if (sc > score) {
					score = sc;
					startbit = sbit;
					bitsize = 1;
					contextdecision = context;
				}
			}
			context = !context;
		}
		while (!context);

		context = true;
		do {
			maxlength = 8 * getMaximumLength(context);
			for (size = 2; size <= 8; ++size) {
				for (sbit = 0; sbit < maxlength - size + 1; ++sbit) {
					if (getNumFixed(sbit, size, context) < maxfixed) {
						continue; // Consider only maximal fields
					}
					sc = getScore(sbit, size, context);
					if (sc > score) {
						score = sc;
						startbit = sbit;
						bitsize = size;
						contextdecision = context;
					}
				}
			}
			context = !context;
		}
		while (!context);
		if (score <= 0.0) { // If we failed to get a positive score
			bitsize = 0; // treat the node as terminal
		}
	}

	// Produce all possible values of -pat- by
	// iterating through all possible values of the
	// "don't care" bits within the value of -pat-
	// that intersects with this node (startbit,bitsize,context)
	private void consistentValues(VectorSTL<Integer> bins, DisjointPattern pat) {
		long m = (bitsize == 32) ? 0 : (1 << bitsize);
		m = m - 1;
		int commonMask = (int) (m & pat.getMask(startbit, bitsize, contextdecision));
		int commonValue = commonMask & pat.getValue(startbit, bitsize, contextdecision);
		long dontCareMask = m ^ commonMask;

		for (int i = 0; i <= dontCareMask; ++i) { // Iterate over values that contain all don't
														// care bits
			if ((i & dontCareMask) != i) {
				continue; // If all 1 bits in the value are don't cares
			}
			bins.push_back(commonValue | i); // add 1 bits into full value and store
		}
	}

	void split(DecisionProperties props)

	{
		if (list.size() <= 1) {
			bitsize = 0; // Only one pattern, terminal node by default
			return;
		}

		chooseOptimalField();
		if (bitsize == 0) {
			orderPatterns(props);
			return;
		}
		if ((parent != null) && (list.size() >= parent.num)) {
			throw new LowlevelError("Child has as many Patterns as parent");
		}

		int numChildren = 1 << bitsize;

		for (int i = 0; i < numChildren; ++i) {
			DecisionNode nd = new DecisionNode(this);
			children.push_back(nd);
		}
		for (int i = 0; i < list.size(); ++i) {
			VectorSTL<Integer> vals = new VectorSTL<>(); // Bins this pattern belongs in
			// If the pattern does not care about some
			// bits in the field we are splitting on, that
			// pattern will get put into multiple bins
			consistentValues(vals, list.get(i).first);
			for (int j = 0; j < vals.size(); ++j) {
				children.get(vals.get(j)).addConstructorPair(list.get(i).first, list.get(i).second);
			}
			list.get(i).first.dispose(); // We no longer need original pattern
		}
		list.clear();

		for (int i = 0; i < numChildren; ++i) {
			children.get(i).split(props);
		}
	}

	// This is a tricky routine.  When this routine is called, the patterns remaining in the
	// the decision node can no longer be distinguished by examining additional bits. The basic
	// idea here is that the patterns should be ordered so that the most specialized should come
	// first in the list. Pattern 1 is a specialization of pattern 2, if the set of instructions
	// matching 1 is contained in the set matching 2.  So in the simplest case, the pattern order
	// should represent a strict nesting.  Unfortunately, there are many potential situations where
	// patterns don't necessarily nest.
	//   1) An "or" of two patterns.  This can be an explicit '|' operator in the Constructor, in
	//      which case this can be detected because the two patterns point to the same constructor
	//      But the "or" can be implied across two constructors that do the same thing.  This should
	//      probably be flagged as an error except in the following case.
	//   2) Two patterns aren't properly nested, but they are "resolved" by a third pattern which
	//      covers the intersection of the first two patterns.  Sometimes its easier to specify
	//      three cases that need to be distinguished in this way.
	//   3) Recursive constructors that use a "guard" context bit.  The guard bit is used to prevent
	//      the recursive constructor from matching repeatedly, but it's too much work to put a
	//      constraint an the bit for every other pattern.
	//   4) Other situations where the ability to distinguish between constructors is hidden in
	//      the subconstructors.
	public void orderPatterns(DecisionProperties props) {
		int i, j, k;
		VectorSTL<Pair<DisjointPattern, Constructor>> newlist = list.copy();
		VectorSTL<Pair<DisjointPattern, Constructor>> conflictlist =
			new VectorSTL<>();

		// Check for identical patterns
		for (i = 0; i < list.size(); ++i) {
			for (j = 0; j < i; ++j) {
				DisjointPattern ipat = list.get(i).first;
				DisjointPattern jpat = list.get(j).first;
				if (ipat.identical(jpat)) {
					props.identicalPattern(list.get(i).second, list.get(j).second);
				}
			}
		}

		for (i = 0; i < list.size(); ++i) {
			for (j = 0; j < i; ++j) {
				DisjointPattern ipat = newlist.get(i).first;
				DisjointPattern jpat = list.get(j).first;
				if (ipat.specializes(jpat)) {
					break;
				}
				if (!jpat.specializes(ipat)) { // We have a potential conflict
					Constructor iconst = newlist.get(i).second;
					Constructor jconst = list.get(j).second;
					if (iconst.equals(jconst)) { // This is an OR in the pattern for ONE constructor
						// So there is no conflict
					}
					else {			// A true conflict that needs to be resolved
						conflictlist.push_back(
							new Pair<>(ipat, iconst));
						conflictlist.push_back(
							new Pair<>(jpat, jconst));
					}
				}
			}
			for (k = i - 1; k >= j; --k) {
				list.set(k + 1, list.get(k));
			}
			list.set(j, newlist.get(i));
		}

		// Check if intersection patterns are present, which resolve conflicts
		for (i = 0; i < conflictlist.size(); i += 2) {
			DisjointPattern pat1, pat2;
			Constructor const1, const2;
			pat1 = conflictlist.get(i).first;
			const1 = conflictlist.get(i).second;
			pat2 = conflictlist.get(i + 1).first;
			const2 = conflictlist.get(i + 1).second;
			boolean resolved = false;
			for (j = 0; j < list.size(); ++j) {
				DisjointPattern tpat = list.get(j).first;
				Constructor tconst = list.get(j).second;
				if ((tpat.equals(pat1)) && (tconst.equals(const1))) {
					break; // Ran out of possible specializations
				}
				if ((tpat == pat2) && (tconst == const2)) {
					break;
				}
				if (tpat.resolvesIntersect(pat1, pat2)) {
					resolved = true;
					break;
				}
			}
			if (!resolved) {
				props.conflictingPattern(pat1, const1, pat2, const2);
			}
		}
	}

	Constructor resolve(ParserWalker pos) {
		if (bitsize == 0) { // The node is terminal
			IteratorSTL<Pair<DisjointPattern, Constructor>> iter;
			for (iter = list.begin(); !iter.isEnd(); iter.increment()) {
				if (iter.get().first.isMatch(pos)) {
					return iter.get().second;
				}
			}
			throw new BadDataError(pos.getAddr().getShortcut() + pos.getAddr().toString() +
				": Unable to resolve constructor");
		}
		int val;
		if (contextdecision) {
			val = pos.getContextBits(startbit, bitsize);
		}
		else {
			val = pos.getInstructionBits(startbit, bitsize);
		}
		return children.get(val).resolve(pos);
	}

	void saveXml(PrintStream s) {
		s.append("<decision");
		s.append(" number=\"");
		s.print(num);
		s.append("\"");
		s.append(" context=\"");
		if (contextdecision) {
			s.append("true\"");
		}
		else {
			s.append("false\"");
		}
		s.append(" start=\"");
		s.print(startbit);
		s.append("\"");
		s.append(" size=\"");
		s.print(bitsize);
		s.append("\"");
		s.append(">\n");
		for (int i = 0; i < list.size(); ++i) {
			s.append("<pair id=\"");
			s.print(list.get(i).second.getId());
			s.append("\">\n");
			list.get(i).first.saveXml(s);
			s.append("</pair>\n");
		}
		for (int i = 0; i < children.size(); ++i) {
			children.get(i).saveXml(s);
		}
		s.append("</decision>\n");
	}

	void restoreXml(Element el, DecisionNode par, SubtableSymbol sub) {
		parent = par;
		num = XmlUtils.decodeUnknownInt(el.getAttributeValue("number"));

		contextdecision = XmlUtils.decodeBoolean(el.getAttributeValue("context"));
		startbit = XmlUtils.decodeUnknownInt(el.getAttributeValue("start"));
		bitsize = XmlUtils.decodeUnknownInt(el.getAttributeValue("size"));

		List<?> childlist = el.getChildren();
		Iterator<?> iter = childlist.iterator();
		while (iter.hasNext()) {
			Element child = (Element) iter.next();
			if (child.getName().equals("pair")) {
				int id = XmlUtils.decodeUnknownInt(child.getAttributeValue("id"));
				Constructor ct = sub.getConstructor(id);
				DisjointPattern pat =
					DisjointPattern.restoreDisjoint((Element) child.getChildren().get(0));
				// This increments num addConstructorPair(pat,ct);
				list.push_back(new Pair<>(pat, ct));
				// delete pat; // addConstructorPair makes its own copy
			}
			else if (child.getName().equals("decision")) {
				DecisionNode subnode = new DecisionNode();
				subnode.restoreXml(child, this, sub);
				children.push_back(subnode);
			}
		}
	}

}
