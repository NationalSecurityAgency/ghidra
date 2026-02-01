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
package ghidra.features.bsim.query.protocol;

import java.io.IOException;
import java.io.Writer;

import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Identifiers for a pair of functions
 *
 */
public class PairInput {
	public ExeSpecifier execA;
	public FunctionEntry funcA;
	public ExeSpecifier execB;
	public FunctionEntry funcB;

	public void saveXml(Writer writer) throws IOException {
		writer.append("<pair>\n");
		execA.saveXml(writer);
		funcA.saveXml(writer);
		execB.saveXml(writer);
		funcB.saveXml(writer);
		writer.append("</pair>\n");
	}

	public void restoreXml(XmlPullParser parser) {
		XmlElement startEl = parser.start("pair");
		execA = new ExeSpecifier();
		execA.restoreXml(parser);
		funcA = FunctionEntry.restoreXml(parser);
		execB = new ExeSpecifier();
		execB.restoreXml(parser);
		funcB = FunctionEntry.restoreXml(parser);
		parser.end(startEl);
	}
}
