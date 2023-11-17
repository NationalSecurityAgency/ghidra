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
import ghidra.features.bsim.query.description.VectorResult;
import ghidra.xml.XmlPullParser;

/**
 * Response to a QueryVectorId request to a BSim database.  For each id in the
 * request, return a VectorResult, which contains the corresponding full vector,
 * or return null 
 *
 */
public class ResponseVectorId extends QueryResponseRecord {

	public List<VectorResult> vectorResults;	// List of result objects (or null) one per requested id

	public ResponseVectorId() {
		super("responsevectorid");
		vectorResults = new ArrayList<VectorResult>();
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		for (VectorResult vecResult : vectorResults) {
			if (vecResult == null) {
				fwrite.append(" <null/>\n");
			}
			else {
				vecResult.saveXml(fwrite);
			}
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		parser.start();
		while (parser.peek().isStart()) {
			if (parser.peek().getName().equals("null")) {
				parser.discardSubTree();
				vectorResults.add(null);
			}
			else {
				VectorResult vecResult = new VectorResult();
				vecResult.restoreXml(parser, vectorFactory);
				vectorResults.add(vecResult);
			}
		}
		parser.end();
	}

}
