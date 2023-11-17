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

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Response to a PrewarmRequest indicating that number of database blocks that were preloaded
 *
 */
public class ResponsePrewarm extends QueryResponseRecord {

	public int blockCount;				// Number of blocks in main index that were read
	public boolean operationSupported;	// true if the back-end supports this operation

	public ResponsePrewarm() {
		super("responseprewarm");
		blockCount = -1;
		operationSupported = true;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name);
		fwrite.append(" support=\"").append(SpecXmlUtils.encodeBoolean(operationSupported));
		fwrite.append("\">\n");
		Integer.toString(blockCount);
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		XmlElement el = parser.start(name);
		operationSupported = SpecXmlUtils.decodeBoolean(el.getAttribute("support"));
		blockCount = SpecXmlUtils.decodeInt(parser.end().getText());
	}

}
