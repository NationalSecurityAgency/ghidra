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
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.pattern;

import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A pattern with no ORs in it
 */
public abstract class DisjointPattern extends Pattern {

	public abstract PatternBlock getBlock(boolean context);

	public PatternBlock getInstructionBlock() {
		return getBlock(false);
	}

	public PatternBlock getContextBlock() {
		return getBlock(true);
	}

	public byte[] getWholeInstructionBytes() {
		return getInstructionBlock().getWholeBytes();
	}

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
		if (block != null)
			return block.getMask(startbit, size);
		return 0;
	}

	public int getValue(int startbit, int size, boolean context) {
		PatternBlock block = getBlock(context);
		if (block != null)
			return block.getValue(startbit, size);
		return 0;
	}

	public int getLength(boolean context) {
		PatternBlock block = getBlock(context);
		if (block != null)
			return block.getLength();
		return 0;
	}

	public boolean specializes(DisjointPattern op2) {
		PatternBlock a, b;

		a = getBlock(false);
		b = op2.getBlock(false);
		if (b != null) {		// a must match existing block
			if (a == null)
				return false;
			if (!a.specializes(b))
				return false;
		}
		a = getBlock(true);
		b = op2.getBlock(true);
		if (b != null) {		// a must match existing block
			if (a == null)
				return false;
			if (!a.specializes(b))
				return false;
		}
		return true;
	}

	public boolean identical(DisjointPattern op2) {
		PatternBlock a, b;

		a = getBlock(false);
		b = op2.getBlock(false);
		if (b != null) {		// a must match existing block
			if (a == null)
				return false;
			if (!a.identical(b))
				return false;
		}
		a = getBlock(true);
		b = op2.getBlock(true);
		if (b != null) {		// a must match existing block
			if (a == null)
				return false;
			if (!a.identical(b))
				return false;
		}
		return true;
	}

	static public DisjointPattern restoreDisjoint(XmlPullParser parser) {
		XmlElement el = parser.peek();
		DisjointPattern res;
		if (el.getName().equals("instruct_pat"))
			res = new InstructionPattern();
		else if (el.getName().equals("context_pat"))
			res = new ContextPattern();
		else
			res = new CombinePattern();
		res.restoreXml(parser);
		return res;
	}
}
