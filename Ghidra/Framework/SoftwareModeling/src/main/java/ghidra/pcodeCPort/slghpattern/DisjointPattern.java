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
package ghidra.pcodeCPort.slghpattern;

import org.jdom.Element;

public abstract class DisjointPattern extends Pattern {

	protected abstract PatternBlock getBlock(boolean context);

	@Override
	public int numDisjoint() {
		return 0;
	}

	@Override
	public DisjointPattern getDisjoint(int i) {
		return null;
	}

	public int getMask(int startbit, int size, boolean context) {
		PatternBlock block = getBlock(context);
		if (block != null) {
			return block.getMask(startbit, size);
		}
		return 0;
	}

	public int getValue(int startbit, int size, boolean context) {
		PatternBlock block = getBlock(context);
		if (block != null) {
			return block.getValue(startbit, size);
		}
		return 0;
	}

	public int getLength(boolean context) {
		PatternBlock block = getBlock(context);
		if (block != null) {
			return block.getLength();
		}
		return 0;
	}

	// Return true, if everywhere this's mask is non-zero
	// op2's mask is non-zero and op2's value match this's
	public boolean specializes(DisjointPattern op2) {
		PatternBlock a = getBlock(false);
		PatternBlock b = op2.getBlock(false);
		if (b != null && (!b.alwaysTrue())) { // a must match existing block
			if (a == null) {
				return false;
			}
			if (!a.specializes(b)) {
				return false;
			}
		}
		a = getBlock(true);
		b = op2.getBlock(true);
		if (b != null && !b.alwaysTrue()) { // a must match existing block
			if (a == null) {
				return false;
			}
			if (!a.specializes(b)) {
				return false;
			}
		}
		return true;
	}

	// Return true is patterns match exactly
	public boolean identical(DisjointPattern op2) {
		PatternBlock a = getBlock(false);
		PatternBlock b = op2.getBlock(false);
		if (b != null) { // a must match existing block
			if (a == null) {
				if (!b.alwaysTrue())
					return false;
			}
			else if (!a.identical(b))
				return false;
		}
		else {
			if ((a != null) && (!a.alwaysTrue()))
				return false;
		}
		a = getBlock(true);
		b = op2.getBlock(true);
		if (b != null) { // a must match existing block
			if (a == null) {
				if (!b.alwaysTrue())
					return false;
			}
			else if (!a.identical(b))
				return false;
		}
		else {
			if ((a != null) && (!a.alwaysTrue()))
				return false;
		}
		return true;
	}

	public static boolean resolveIntersectBlock(PatternBlock bl1, PatternBlock bl2,
			PatternBlock thisblock) {
		PatternBlock inter;
		boolean res = true;

		if (bl1 == null)
			inter = bl2;
		else if (bl2 == null)
			inter = bl1;
		else {
			inter = bl1.intersect(bl2);
		}
		if (inter == null) {
			if (thisblock != null)
				res = false;
		}
		else if (thisblock == null)
			res = false;
		else
			res = thisblock.identical(inter);
		return res;
	}

	public boolean resolvesIntersect(DisjointPattern op1, DisjointPattern op2) {
		// Is this pattern equal to the intersection of -op1- and -op2-
		if (!resolveIntersectBlock(op1.getBlock(false), op2.getBlock(false), getBlock(false)))
			return false;
		return resolveIntersectBlock(op1.getBlock(true), op2.getBlock(true), getBlock(true));
	}

	// DisjointPattern factory
	public static DisjointPattern restoreDisjoint(Element el) {
		DisjointPattern res;
		if (el.getName().equals("instruct_pat")) {
			res = new InstructionPattern();
		}
		else if (el.getName().equals("context_pat")) {
			res = new ContextPattern();
		}
		else {
			res = new CombinePattern();
		}
		res.restoreXml(el);
		return res;
	}

	@Override
	public String toString() {
		return "DisjointPattern{" + getBlock(true) + " : " + getBlock(false) + "}";
	}
}
