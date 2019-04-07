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
import ghidra.pcodeCPort.utils.MutableInt;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

public class NotExpression extends UnaryExpression {

	public NotExpression(Location location) {
		super(location);
	}

	public NotExpression(Location location, PatternExpression u) {
		super(location, u);
	}

	@Override
	public long getValue(ParserWalker pos) {
		long val = getUnary().getValue(pos);
		return ~val;
	}

	@Override
	public long getSubValue(VectorSTL<Long> replace, MutableInt listpos) {
		long val = getUnary().getSubValue(replace, listpos);
		return ~val;
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<not_exp>\n");
		super.saveXml(s);
		s.append("</not_exp>\n");
	}

}
