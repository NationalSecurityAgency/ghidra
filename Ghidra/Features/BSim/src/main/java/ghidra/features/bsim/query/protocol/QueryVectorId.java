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
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlPullParser;

/**
 * Request vectors from the database by the their ids. Allows users to retrieve raw feature
 * vectors without going through functions (FunctionDescription and DescriptionManager)
 */
public class QueryVectorId extends BSimQuery<ResponseVectorId> {

	public List<Long> vectorIds;			// The list of ids to query for
	public ResponseVectorId vectorIdResponse;

	public QueryVectorId() {
		super("queryvectorid");
		vectorIds = new ArrayList<Long>();
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null) {
			response = vectorIdResponse = new ResponseVectorId();
		}
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		for (Long id : vectorIds) {
			fwrite.append("  <id>0x");
			fwrite.append(Long.toHexString(id.longValue()));
			fwrite.append("</id>\n");
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		parser.start();
		while (parser.peek().isStart()) {
			parser.start();
			long val = SpecXmlUtils.decodeLong(parser.end().getText());
			vectorIds.add(val);
		}
		parser.end();
	}

}
