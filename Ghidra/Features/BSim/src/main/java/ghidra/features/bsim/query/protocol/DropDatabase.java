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
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class DropDatabase extends BSimQuery<ResponseDropDatabase> {
	public String databaseName;
	public ResponseDropDatabase dropResponse;

	public DropDatabase() {
		super("dropdatabase");
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = dropResponse = new ResponseDropDatabase();
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(XmlUtilities.escapeElementEntities(name));
		fwrite.append(" dbname=\"").append(databaseName).append("\" />\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) {
		XmlElement el = parser.start(name);
		databaseName = XmlUtilities.unEscapeElementEntities(el.getAttribute("dbname"));
		parser.end();
	}

}
