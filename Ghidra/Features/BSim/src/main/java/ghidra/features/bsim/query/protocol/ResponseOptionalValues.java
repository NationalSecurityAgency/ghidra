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

public class ResponseOptionalValues extends QueryResponseRecord {

	// FIXME: XML serialization assumes String-based resultArray which is incorrect

	public Object[] resultArray;		// Array of values corresponding to queried keys
	public boolean tableExists;			// false if the query failed because the table doesn't exist

	public ResponseOptionalValues() {
		super("responseoptionalvalues");
		resultArray = null;
		tableExists = true;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		if (!tableExists) {
			fwrite.append("<exists>false</exists>\n");
		}
		if (resultArray != null) {
			for (Object value : resultArray) {
				fwrite.append("<val>");
				SpecXmlUtils.xmlEscapeWriter(fwrite, value.toString());
				fwrite.append("</val>\n");
			}
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		tableExists = true;
		resultArray = null;
		List<Object> resValues = new ArrayList<Object>();
		parser.start(name);
		if (parser.peek().getName().equals("exists")) {
			parser.start("exists");
			tableExists = SpecXmlUtils.decodeBoolean(parser.end().getText());
		}
		while (parser.peek().isStart()) {
			parser.start();
			String value = parser.end().getText();
			resValues.add(value);
		}
		parser.end();
		if (!resValues.isEmpty()) {
			resultArray = new Object[resValues.size()];
			resValues.toArray(resultArray);
		}
	}

}
