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
 * Response to a QueryOptionalExist, reporting whether an optional table exists
 */
public class ResponseOptionalExist extends QueryResponseRecord {

	public boolean tableExists;		// true if the queried table exists
	public boolean wasCreated;		// true if this query caused creation of table

	public ResponseOptionalExist() {
		super("responseoptionalexist");
		tableExists = false;
		wasCreated = false;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		if (tableExists) {
			fwrite.append("<exists>true</exist>\n");
		}
		else {
			fwrite.append("<exists>false</exists>\n");
		}
		if (wasCreated) {
			fwrite.append("<created>true</created>\n");
		}
		else {
			fwrite.append("<created>false</created>\n");
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		tableExists = false;
		wasCreated = false;
		parser.start(name);
		if (parser.peek().getName().equals("exists")) {
			parser.start();
			tableExists = SpecXmlUtils.decodeBoolean(parser.end().getText());
		}
		if (parser.peek().getName().equals("created")) {
			parser.start();
			tableExists = SpecXmlUtils.decodeBoolean(parser.end().getText());
		}
		parser.end();
	}

}
