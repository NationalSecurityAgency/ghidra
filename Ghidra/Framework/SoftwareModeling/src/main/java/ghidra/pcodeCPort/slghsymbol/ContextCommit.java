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
package ghidra.pcodeCPort.slghsymbol;

import ghidra.pcodeCPort.context.ParserWalkerChange;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.utils.*;

import java.io.PrintStream;

import org.jdom.Element;

public class ContextCommit extends ContextChange {

	private TripleSymbol sym;
	private int num; // Index of word containing context commit
	private int mask; // mask of bits in word being committed
	private boolean flow; // Whether the context "flows" from the point of change

	public ContextCommit() {
	} // For use with restoreXml

	@Override
	public void validate() {
	}

	public ContextCommit(TripleSymbol s, int sbit, int ebit, boolean fl) {
		sym = s;
		flow = fl;
		MutableInt n = new MutableInt();
		MutableInt zero = new MutableInt(0);
		MutableInt m = new MutableInt();
		Utils.calc_maskword(s.getLocation(), sbit, ebit, n, zero, m);
		num = n.get();
		mask = m.get();
	}

	@Override
	public void apply(ParserWalkerChange pos) {
		pos.getParserContext().addCommit(sym, num, mask, flow, pos.getPoint());

	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<commit");
		XmlUtils.a_v_u(s, "id", sym.getId());
		XmlUtils.a_v_i(s, "num", num);
		XmlUtils.a_v_u(s, "mask", Utils.unsignedInt(mask));
		XmlUtils.a_v_b(s, "flow", flow);
		s.append("/>\n");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {
		int id = XmlUtils.decodeUnknownInt(el.getAttributeValue("id"));
		sym = (TripleSymbol) trans.findSymbol(id);

		num = XmlUtils.decodeUnknownInt(el.getAttributeValue("num"));
		mask = XmlUtils.decodeUnknownInt(el.getAttributeValue("mask"));
		String value = el.getAttributeValue("flow");
		if (value != null) {
			flow = XmlUtils.decodeBoolean(value);
		}
		else {
			flow = true;
		}
	}

}
