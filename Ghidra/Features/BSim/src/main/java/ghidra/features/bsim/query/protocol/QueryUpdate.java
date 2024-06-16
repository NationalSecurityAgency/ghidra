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
import ghidra.xml.XmlPullParser;

/**
 * Request to update the metadata fields of various ExecutableRecords and FunctionDescriptions within a BSim database.
 * This allows quick updates of metadata fields like executable names, function names, and other descriptive metadata fields,
 * without affecting the main index. ExecutableRecord descriptions will be replaced based on the md5 of the executable,
 * and FunctionDescriptions are replaced based on their address within an identified executable.
 * within an executable.
 *
 */
public class QueryUpdate extends BSimQuery<ResponseUpdate> {

	public DescriptionManager manage;	// contains the list of ExecutableRecords and FunctionDescriptions to update
	public ResponseUpdate updateresponse;
	
	public QueryUpdate() {
		super("update");
		manage = new DescriptionManager();
	}
	
	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = updateresponse = new ResponseUpdate(this);
	}

	@Override
	public DescriptionManager getDescriptionManager() {
		return manage;
	}

	@Override
	public QueryUpdate getLocalStagingCopy() {
		QueryUpdate newq = new QueryUpdate();
		return newq;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		manage.saveXml(fwrite);
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		parser.start(name);
		manage.restoreXml(parser, vectorFactory);
		parser.end();
	}

}
