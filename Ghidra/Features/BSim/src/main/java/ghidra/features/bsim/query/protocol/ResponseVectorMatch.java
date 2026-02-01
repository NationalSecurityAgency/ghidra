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
 * Response to a request for functions with specific vector ids
 * Full ExecutableRecords and FunctionDescriptions are instantiated in this object's DescriptionManager
 */
public class ResponseVectorMatch extends QueryResponseRecord {

	public DescriptionManager manage;		// Set of functions (and executables) matching vector id request

	public ResponseVectorMatch() {
		super("responsevectormatch");
		manage = new DescriptionManager();
	}

	@Override
	public DescriptionManager getDescriptionManager() {
		return manage;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		manage.saveXml(fwrite);
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		parser.start(name);
		manage.restoreXml(parser, vectorFactory);
		parser.end();
	}
}
