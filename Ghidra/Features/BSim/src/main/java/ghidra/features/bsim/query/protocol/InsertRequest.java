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
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Request that specific executables and functions (as described by ExecutableRecords and FunctionDescriptions)
 * by inserted into a BSim database.
 *
 */
public class InsertRequest extends BSimQuery<ResponseInsert> {

	public DescriptionManager manage;		// The set of executables and functions to be inserted
	public String repo_override;			// Override of repository for this insert
	public String path_override;			// Override of path
	public ResponseInsert insertresponse;
	
	public InsertRequest() {
		super("insert");
		manage = new DescriptionManager();
		repo_override = null;
		path_override = null;
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = insertresponse = new ResponseInsert();
	}

	@Override
	public DescriptionManager getDescriptionManager() {
		return manage;
	}

	@Override
	public InsertRequest getLocalStagingCopy() {
		InsertRequest newi = new InsertRequest();
		newi.repo_override = repo_override;
		newi.path_override = path_override;
		return newi;
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		manage.saveXml(fwrite);
		if (repo_override != null)
			fwrite.append("<repository>").append(repo_override).append("</repository>\n");
		if (path_override != null)
			fwrite.append("<path>").append(path_override).append("</path>\n");
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser,LSHVectorFactory vectorFactory) throws LSHException {
		parser.start(name);
		manage.restoreXml(parser,vectorFactory);
		XmlElement subel = parser.peek();
		while(subel.isStart()) {
			if (subel.getName().equals("repository")) {		// Optional repository
				parser.start("repository");
				repo_override = parser.end().getText();
			}
			else if (subel.getName().equals("path")) {		// Optional path
				parser.start("path");
				path_override = parser.end().getText();
			}
			subel = parser.peek();
		}
		parser.end();
	}

}
