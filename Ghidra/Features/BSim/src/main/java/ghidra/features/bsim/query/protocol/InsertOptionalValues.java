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
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Insert key/value pairs into an optional table
 */
public class InsertOptionalValues extends BSimQuery<ResponseOptionalExist> {

	public ResponseOptionalExist optionalresponse = null;
	public String tableName;		// Name of optional SQL table
	public int keyType;				// type-code of key as per java.sql.Types
	public int valueType;			// type-code of value
	public Object[] keys;			// keys to be inserted
	public Object[] values;			// values (corresponding to keys) to be inserted

	public InsertOptionalValues() {
		super("insertoptionalvalues");
		tableName = null;
		keyType = -1;
		valueType = -1;
		keys = null;
		values = null;
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null) {
			response = optionalresponse = new ResponseOptionalExist();
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
		for (Object val : values) {
			fwrite.append("<val>");
			SpecXmlUtils.xmlEscapeWriter(fwrite, val.toString());
			fwrite.append("</val>\n");
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		keys = null;
		values = null;
		List<String> resultKeys = new ArrayList<String>();
		List<String> resultValues = new ArrayList<String>();
		parser.start(name);
		parser.start("tablename");
		tableName = parser.end().getText();
		parser.start("keytype");
		keyType = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("valuetype");
		valueType = SpecXmlUtils.decodeInt(parser.end().getText());
		while (parser.peek().isStart()) {
			XmlElement el = parser.start();
			String nm = el.getName();
			String body = parser.end().getText();
			if (nm.equals("key")) {
				resultKeys.add(body);
			}
			else {
				resultValues.add(body);
			}
		}
		parser.end();
		if (!resultKeys.isEmpty()) {
			keys = new Object[resultKeys.size()];
			values = new Object[resultValues.size()];
			resultKeys.toArray(keys);
			resultValues.toArray(values);
		}
	}

}
