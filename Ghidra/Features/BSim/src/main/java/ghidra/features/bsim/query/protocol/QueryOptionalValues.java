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
 * Query for values from an optional table, given a set of keys
 */
public class QueryOptionalValues extends BSimQuery<ResponseOptionalValues> {

	public ResponseOptionalValues optionalresponse = null;
	public Object[] keys;		// Keys to query
	public String tableName;	// Name of the optional table
	public int keyType;			// Type of the key, as per java.sql.Types
	public int valueType;		// Type of the value

	public QueryOptionalValues() {
		super("queryoptionalvalues");
		tableName = null;
		keys = null;
		keyType = -1;
		valueType = -1;
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null) {
			response = optionalresponse = new ResponseOptionalValues();
		}
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		fwrite.append("<tablename>");
		SpecXmlUtils.xmlEscapeWriter(fwrite, tableName);
		fwrite.append("</tablename>\n");
		fwrite.append("<keytype>");
		fwrite.append(Integer.toString(keyType));
		fwrite.append("</keytype>\n");
		fwrite.append("<valuetype>");
		fwrite.append(Integer.toString(valueType));
		fwrite.append("</valuetype>\n");
		for (Object key : keys) {
			fwrite.append("<key>");
			SpecXmlUtils.xmlEscapeWriter(fwrite, key.toString());
			fwrite.append("</key>\n");
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		keys = null;
		List<String> resultKeys = new ArrayList<String>();
		parser.start(name);
		parser.start("tablename");
		tableName = parser.end().getText();
		parser.start("keytype");
		keyType = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("valuetype");
		valueType = SpecXmlUtils.decodeInt(parser.end().getText());
		while (parser.peek().isStart()) {
			parser.start();
			String key = parser.end().getText();
			resultKeys.add(key);
		}
		parser.end();
		if (!resultKeys.isEmpty()) {
			keys = new Object[resultKeys.size()];
			resultKeys.toArray(keys);
		}
	}

}
