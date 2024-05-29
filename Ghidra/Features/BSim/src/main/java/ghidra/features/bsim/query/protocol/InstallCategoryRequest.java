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
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Request that a new executable category be installed for a specific BSim server.
 *
 */
public class InstallCategoryRequest extends BSimQuery<ResponseInfo> {

	public String type_name;		// Name of new type of category
	public boolean isdatecolumn;	// True if name should be treated as new name for date column
	public ResponseInfo installresponse;
	
	public InstallCategoryRequest() {
		super("installcategory");
		type_name = "";
		isdatecolumn = false;
	}
	
	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = installresponse = new ResponseInfo();
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		if (!CategoryRecord.enforceTypeCharacters(type_name))
			throw new IOException("Bad characters in requested category type");
		fwrite.append('<').append(name);
		if (isdatecolumn)
			fwrite.append(" datecolumn=\"true\"");
		fwrite.append('>');
		fwrite.append(type_name);
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		XmlElement el = parser.start(name);
		isdatecolumn = XmlUtilities.parseBoolean(el.getAttribute("datecolumn"));
		type_name = parser.end().getText();
	}

}
