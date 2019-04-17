/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.slghpattern;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.ParserWalker;

import java.io.PrintStream;
import java.util.Iterator;
import java.util.List;

import org.jdom.Element;

public class OrPattern extends Pattern {

	private VectorSTL<DisjointPattern> orlist = new VectorSTL<DisjointPattern>();

	public OrPattern() {
	} // For use with restoreXml

	@Override
	public int numDisjoint() {
		return orlist.size();
	}

	@Override
	public DisjointPattern getDisjoint(int i) {
		return orlist.get(i);
	}

	public OrPattern(DisjointPattern a, DisjointPattern b) {
		orlist.push_back(a);
		orlist.push_back(b);
	}

	public OrPattern(VectorSTL<DisjointPattern> list) {
		IteratorSTL<DisjointPattern> iter;
		for (iter = list.begin(); !iter.isEnd(); iter.increment()) {
			orlist.push_back(iter.get());
		}
	}

	@Override
	public void dispose() {
		IteratorSTL<DisjointPattern> iter;
		for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
			iter.get().dispose();
		}
	}

	@Override
	public void shiftInstruction(int sa) {
		IteratorSTL<DisjointPattern> iter;
		for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
			iter.get().shiftInstruction(sa);
		}
	}

	@Override
	public boolean isMatch(ParserWalker pos) {
		for (int i = 0; i < orlist.size(); ++i) {
			if (orlist.get(i).isMatch(pos)) {
				return true;
			}
		}
		return false;
	}

	// This isn't quite right because different branches
	// may cover the entire gamut
	@Override
	public boolean alwaysTrue() {
		IteratorSTL<DisjointPattern> iter;

		for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
			if (iter.get().alwaysTrue()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean alwaysFalse() {
		IteratorSTL<DisjointPattern> iter;

		for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
			if (!iter.get().alwaysFalse()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean alwaysInstructionTrue() {
		IteratorSTL<DisjointPattern> iter;

		for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
			if (!iter.get().alwaysInstructionTrue()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public Pattern doAnd(Pattern b, int sa) {
		VectorSTL<DisjointPattern> newlist = new VectorSTL<DisjointPattern>();
		if (b instanceof OrPattern) {
			OrPattern b2 = (OrPattern) b;
			IteratorSTL<DisjointPattern> iter, iter2;
			for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
				for (iter2 = b2.orlist.begin(); !iter2.isEnd(); iter2.increment()) {
					DisjointPattern tmp = (DisjointPattern) iter.get().doAnd(iter2.get(), sa);
					newlist.push_back(tmp);
				}
			}
		}
		else {
			IteratorSTL<DisjointPattern> iter;
			for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
				DisjointPattern tmp = (DisjointPattern) iter.get().doAnd(b, sa);
				newlist.push_back(tmp);
			}
		}
		return new OrPattern(newlist);
	}

	@Override
	public Pattern commonSubPattern(Pattern b, int sa) {
		IteratorSTL<DisjointPattern> iter;
		Pattern res, next;

		iter = orlist.begin();
		res = iter.get().commonSubPattern(b, sa);
		iter.increment();

		if (sa > 0) {
			sa = 0;
		}
		while (!iter.isEnd()) {
			next = iter.get().commonSubPattern(res, sa);
			res.dispose();
			res = next;
			iter.increment();
		}
		return res;
	}

	@Override
	public Pattern doOr(Pattern b, int sa) {
		VectorSTL<DisjointPattern> newlist = new VectorSTL<DisjointPattern>();
		IteratorSTL<DisjointPattern> iter;

		for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
			newlist.push_back((DisjointPattern) iter.get().simplifyClone());
		}
		if (sa < 0) {
			for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {
				iter.get().shiftInstruction(-sa);
			}
		}
		if (!(b instanceof OrPattern)) {
			newlist.push_back((DisjointPattern) b.simplifyClone());
		}
		else {
			OrPattern b2 = (OrPattern) b;
			for (iter = b2.orlist.begin(); !iter.equals(b2.orlist.end()); iter.increment()) {
				newlist.push_back((DisjointPattern) iter.get().simplifyClone());
			}
		}
		if (sa > 0) {
			for (int i = 0; i < newlist.size(); ++i) {
				newlist.get(i).shiftInstruction(sa);
			}
		}

		return new OrPattern(newlist);
	}

	// Look for alwaysTrue eliminate alwaysFalse
	@Override
	public Pattern simplifyClone() {
		IteratorSTL<DisjointPattern> iter;

		for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {// Look for alwaysTrue
			if (iter.get().alwaysTrue()) {
				return new InstructionPattern(true);
			}
		}

		VectorSTL<DisjointPattern> newlist = new VectorSTL<DisjointPattern>();
		for (iter = orlist.begin(); !iter.isEnd(); iter.increment()) {// Look for alwaysFalse
			if (!iter.get().alwaysFalse()) {
				newlist.push_back((DisjointPattern) iter.get().simplifyClone());
			}
		}

		if (newlist.empty()) {
			return new InstructionPattern(false);
		}
		else if (newlist.size() == 1) {
			return newlist.get(0);
		}
		return new OrPattern(newlist);
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<or_pat>\n");
		for (int i = 0; i < orlist.size(); ++i) {
			orlist.get(i).saveXml(s);
		}
		s.append("</or_pat>\n");
	}

	@Override
	public void restoreXml(Element el) {
		List<?> list = el.getChildren();
		Iterator<?> iter = list.iterator();
		while (iter.hasNext()) {
			Element element = (Element) iter.next();
			DisjointPattern pat = DisjointPattern.restoreDisjoint(element);
			orlist.push_back(pat);
		}
	}

}
