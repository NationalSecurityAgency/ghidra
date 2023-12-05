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
import ghidra.xml.XmlPullParser;

/**
 * Query whether an optional table exists. If it doesn't exist it can be created.
 * If it exists, it can be cleared
 */
public class QueryOptionalExist extends BSimQuery<ResponseOptionalExist> {

	public ResponseOptionalExist optionalresponse = null;
	public String tableName;	// Formal SQL name of the table
	public int keyType;			// type-code for the key column (from java.sql.Types)
	public int valueType;		// type-code for the value column
	public boolean attemptCreation;		// true if we should create the table if it doesn't exist
	public boolean clearTable;	// If true and table already exists, clear all rows of the table

	public QueryOptionalExist() {
		super("queryoptionalexist");
		tableName = null;
		keyType = -1;
		valueType = -1;
		attemptCreation = false;
		clearTable = false;
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
		if (attemptCreation) {
			fwrite.append("<create>true</create>\n");
		}
		else {
			fwrite.append("<create>false</create>\n");
		}
		if (clearTable) {
			fwrite.append("<clear>true</clear>\n");
		}
		else {
			fwrite.append("<clear>false</clear>\n");
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		parser.start(name);
		parser.start("tablename");
		tableName = parser.end().getText();
		parser.start("keytype");
		keyType = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("valuetype");
		valueType = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("create");
		attemptCreation = SpecXmlUtils.decodeBoolean(parser.end().getText());
		parser.start("clear");
		clearTable = SpecXmlUtils.decodeBoolean(parser.end().getText());
		parser.end();
	}

}
