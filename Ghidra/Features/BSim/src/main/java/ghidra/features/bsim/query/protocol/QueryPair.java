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
import java.util.ArrayList;
import java.util.List;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A list of descriptor pairs to be sent to the server.
 * Each pair describes a pair of functions in the database whose vectors are to be compared
 *
 */
public class QueryPair extends BSimQuery<ResponsePair> {

	public List<PairInput> pairs;
	public ResponsePair pairResponse;

	public QueryPair() {
		super("querypair");
		pairs = new ArrayList<PairInput>();
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = pairResponse = new ResponsePair();
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		for (PairInput pairInput : pairs) {
			pairInput.saveXml(fwrite);
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		XmlElement startEl = parser.start(name);
		for (;;) {
			XmlElement note = parser.peek();
			if (!note.isStart())
				break;
			PairInput pairInput = new PairInput();
			pairInput.restoreXml(parser);
			pairs.add(pairInput);
		}
		parser.end(startEl);
	}
}
