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
import ghidra.features.bsim.query.description.CategoryRecord;
import ghidra.xml.XmlPullParser;

/**
 * Request that a new function tag be installed for a specific BSim server
 *
 */
public class InstallTagRequest extends BSimQuery<ResponseInfo> {

	public String tag_name;			// Name of new function tag

	public ResponseInfo installresponse;
	
	public InstallTagRequest() {
		super("installtag");
		tag_name = "";
	}
	
	@Override
	public void buildResponseTemplate() {
		if (response == null) {
			response = installresponse = new ResponseInfo();
		}
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		if (!CategoryRecord.enforceTypeCharacters(tag_name)) {
			throw new IOException("Bad characters in requested category type");
		}
		fwrite.append('<').append(name);
		fwrite.append('>');
		fwrite.append(tag_name);
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		parser.start(name);
		tag_name = parser.end().getText();
	}

}
