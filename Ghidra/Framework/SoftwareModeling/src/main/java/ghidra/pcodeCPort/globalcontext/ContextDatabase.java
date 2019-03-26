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
package ghidra.pcodeCPort.globalcontext;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.MutableLong;
import ghidra.pcodeCPort.utils.Utils;

import java.io.PrintStream;
import java.util.Iterator;
import java.util.List;

import org.jdom.Element;

/**
 * This is the interface and implementation for a database of memory locations which should be
 * treated likeants. These come in two flavors:
 * <p>
 * 1) Low-level context variables These can affect instruction decoding. These can be as small as a
 * single bit and need to be defined in the sleigh module (so that sleigh knows how they effect
 * disassembly). These variables are not mapped to normal memory locations with a space and offset.
 * (Although they often have a corresponding embedding into a normal memory location) The model to
 * keep in mind is special bitfields within a control register.
 * <p>
 * 2) High-level tracked variables These are normal memory locations that are to be treated asants
 * across some range of code. These are normally some register that is being kept track of be the
 * compiler outside the domain of normal local and global variables. They have a specific value
 * established by the compiler coming in to a function but are not supposed to be interpreted as a
 * high-level variable. Typical examples are the String instruction direction flag and segment
 * registers. These are all interpreted as aant value at the start of a function, but the function
 * can recycle the memory location for other calculations once theant has been used.
 */
public abstract class ContextDatabase {

	public void dispose() {
	}

	public abstract int getContextSize();

	public abstract void registerVariable(String nm, int sbit, int ebit);

	public abstract ContextBitRange getVariable(String nm);

	public abstract void getRegion(VectorSTL<int[]> res, Address addr1, Address addr2);

	public abstract int[] getContext(Address addr);

	public abstract int[] getContext(Address addr, MutableLong first, MutableLong last);

	public abstract int[] getDefaultValue();

	public abstract int[] createContext(Address addr);

	public abstract VectorSTL<TrackedContext> getTrackedDefault();

	public abstract VectorSTL<TrackedContext> getTrackedSet(Address addr);

	public abstract VectorSTL<TrackedContext> createSet(Address addr1, Address addr2);

	public abstract void saveXml(PrintStream s);

	public abstract void restoreXml(Element el, Translate translate);

	public abstract void restoreFromSpec(Element el, Translate translate);

	protected void saveTracked(PrintStream s, Address addr, VectorSTL<TrackedContext> vec) {
		if (vec.empty()) {
			return;
		}
		s.append("<tracked_pointset");
		addr.getSpace().saveXmlAttributes(s, addr.getOffset());
		s.append(">\n");
		for (int i = 0; i < vec.size(); ++i) {
			s.append("  ");
			vec.get(i).saveXml(s);
		}
		s.append("</tracked_pointset>\n");
	}

	public void setVariableDefault(String nm, int val) {
		ContextBitRange var = getVariable(nm);
		var.setValue(getDefaultValue(), val);
	}

	public int getDefaultValue(String nm) {
		ContextBitRange var = getVariable(nm);
		return var.getValue(getDefaultValue());
	}

	/** Set value of context register, starting at addr */
	public void setVariable(String nm, Address addr, int value) {
		ContextBitRange bitrange = getVariable(nm);

		int[] newcontext = createContext(addr);
		bitrange.setValue(newcontext, value);
	}

	public int getVariable(String nm, Address addr) {
		ContextBitRange bitrange = getVariable(nm);

		int[] context = getContext(addr);
		return bitrange.getValue(context);
	}

	/** Set specific bits in context */
	public void setContextRange(Address addr, int num, int mask, int value) {
		int[] newcontext = createContext(addr);

		int val = newcontext[num];
		val &= ~mask; // Clear range to zero
		val |= value;
		newcontext[num] = val;
	}

	/** Set value of context register between begad and endad */
	public void setVariableRegion(String nm, Address begad, Address endad, int value) {
		ContextBitRange bitrange = getVariable(nm);

		VectorSTL<int[]> vec = new VectorSTL<int[]>();
		getRegion(vec, begad, endad);
		for (int i = 0; i < vec.size(); ++i) {
			bitrange.setValue(vec.get(i), value);
		}
	}

	/**
	 * For a particular tracked memory location, get the value at a particular point.
	 */
	public long getTrackedValue(VarnodeData mem, Address point) {
		VectorSTL<TrackedContext> tset = getTrackedSet(point);
		long endoff = mem.offset + mem.size - 1;
		long tendoff;
		for (int i = 0; i < tset.size(); ++i) {
			TrackedContext tcont = tset.get(i);
			if (tcont == null) {
				tcont = new TrackedContext();
				tset.set(i, tcont);
			}

			// tcont must contain -mem-
			if (tcont.loc.space != mem.space) {
				continue;
			}
			if (tcont.loc.offset > mem.offset) {
				continue;
			}
			tendoff = tcont.loc.offset + tcont.loc.size - 1;
			if (tendoff < endoff) {
				continue;
			}

			long res = tcont.val;
			// If we have proper containment, trim value based on endianness
			if (tcont.loc.space.isBigEndian()) {
				if (endoff != tendoff) {
					res >>>= (8 * (tendoff - mem.offset));
				}
			}
			else {
				if (mem.offset != tcont.loc.offset) {
					res >>>= (8 * (mem.offset - tcont.loc.offset));
				}
			}
			res &= Utils.calc_mask(mem.size); // Final trim based on size
			return res;
		}
		return 0;
	}

	public static void restoreTracked(Element el, Translate trans, VectorSTL<TrackedContext> vec) {
		vec.clear();

		List<?> list = el.getChildren();
		Iterator<?> iter = list.iterator();

		while (iter.hasNext()) {
			Element subel = (Element) iter.next();
			vec.push_back(new TrackedContext());
			vec.back().restoreXml(subel, trans);
		}
	}

}
