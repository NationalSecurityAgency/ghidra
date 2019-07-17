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
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

public class StartInstructionValue extends PatternValue {

	public StartInstructionValue(Location location) {
		super(location);
	}

	@Override
	public long getValue(ParserWalker pos) {
		return (pos.getAddr().getOffset() >> pos.getAddr().getSpace().getScale());
	}

	@Override
	public TokenPattern genMinPattern(VectorSTL<TokenPattern> ops) {
		return new TokenPattern(location);
	}

	@Override
	public TokenPattern genPattern(long val) {
		return new TokenPattern(location);
	}

	@Override
	public long minValue() {
		return 0;
	}

	@Override
	public long maxValue() {
		return 0;
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<start_exp/>");
	}

	@Override
	public void restoreXml(Element el, Translate trans) {
	}

}
