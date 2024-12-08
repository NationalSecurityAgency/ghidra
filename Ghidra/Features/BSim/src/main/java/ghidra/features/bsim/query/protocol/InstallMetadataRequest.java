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
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Request that the high-level meta-data fields (name,owner,description) of a database be changed
 *
 */
public class InstallMetadataRequest extends BSimQuery<ResponseInfo> {

	public String dbname;		// New name of database (if null, old value will be retained)
	public String owner;		// New owner of database (if null, old value will be retained)
	public String description;  // New description for database (if null, old value will be retained)
	
	public ResponseInfo installresponse;
	
	public InstallMetadataRequest() {
		super("installmetadata");
	}
	
	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = installresponse = new ResponseInfo();
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		if (dbname!=null && dbname.length()!=0)
			fwrite.append("<name>").append(XmlUtilities.escapeElementEntities(dbname)).append("</name>\n");
		if (owner!=null && owner.length()!=0)
			fwrite.append("<owner>").append(XmlUtilities.escapeElementEntities(owner)).append("</owner>\n");
		if (description!=null && description.length()!=0)
			fwrite.append("<description>").append(XmlUtilities.escapeElementEntities(description)).append("</description>\n");
		fwrite.append("</").append(name).append(">\n");
	}


	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		dbname = null;
		owner = null;
		description = null;
		parser.start(name);
		while(parser.peek().isStart()) {
			XmlElement start = parser.start();
			String elname = start.getName();
			String val = parser.end().getText();
			if (elname.equals("name"))
				dbname = val;
			else if (elname.equals("owner"))
				owner = val;
			else if (elname.equals("description"))
				description = val;
		}
		parser.end();
	}

}
