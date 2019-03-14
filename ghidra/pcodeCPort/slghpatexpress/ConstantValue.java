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
package ghidra.pcodeCPort.slghpatexpress;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

public class ConstantValue extends PatternValue {

	long val;

	public ConstantValue(Location location) {
		super(location);
	} // For use with restoreXml

	public ConstantValue(Location location, long v) {
		super(location);
		val = v;
	}

	@Override
	public long getValue(ParserWalker pos) {
		return val;
	}

	@Override
	public TokenPattern genMinPattern(VectorSTL<TokenPattern> ops) {
		return new TokenPattern(location);
	}

	@Override
	public TokenPattern genPattern(long v) {
		return new TokenPattern(location, val == v);
	}

	@Override
	public long minValue() {
		return val;
	}

	@Override
	public long maxValue() {
		return val;
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<intb val=\"");
		s.print(val);
		s.append("\"/>\n");
	}

	@Override
	public void restoreXml(Element el, Translate trans) {
		val = XmlUtils.decodeUnknownLong(el.getAttributeValue("val"));
	}

}
