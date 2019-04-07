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
package ghidra.app.plugin.processors.sleigh;

import ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class ContextCommit implements ContextChange {

	private TripleSymbol sym;
	private int num;
	private int mask;

	public ContextCommit() {
		sym = null;
	}

	public void apply(ParserWalker walker, SleighDebugLogger debug) throws MemoryAccessException {
		walker.getParserContext().addCommit(walker.getState(), sym, num, mask);
		if (debug != null) {
			debug.dumpGlobalSet(walker.getParserContext(), walker.getState(), sym, num, mask,
				walker.getParserContext().getContextBytes()[num] & mask);
		}
	}

	public void restoreXml(XmlPullParser parser, SleighLanguage lang) {
		XmlElement el = parser.start("commit");
		int id = SpecXmlUtils.decodeInt(el.getAttribute("id"));
		sym = (TripleSymbol) lang.getSymbolTable().findSymbol(id);
		num = SpecXmlUtils.decodeInt(el.getAttribute("num"));
		mask = SpecXmlUtils.decodeInt(el.getAttribute("mask"));
		parser.end(el);
	}

}
