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
import ghidra.features.bsim.query.description.*;
import ghidra.xml.XmlPullParser;

/**
 * Response to a QueryChildren request to a BSim database.  A full FunctionDescription is returned for
 * every name in the original request and their children (1-level).  The FunctionDescriptions corresponding
 * to the original list of function names are also collected in the -correspond- array.
 *
 */
public class ResponseChildren extends QueryResponseRecord {

	public DescriptionManager manage;	// A description of the originally requested functions and their children
	public List<FunctionDescription> correspond;	// The list of originally requested FunctionDescriptions
	public QueryChildren qchild;		// The original query for which this is a response

	public ResponseChildren(QueryChildren qc) {
		super("responsechildren");
		manage = new DescriptionManager();
		correspond = new ArrayList<FunctionDescription>();
		qchild = qc;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		manage.saveXml(fwrite);
		if (!correspond.isEmpty()) {
			fwrite.append("<md5>");
			fwrite.append(correspond.get(0).getExecutableRecord().getMd5());
			fwrite.append("</md5>\n");
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		parser.start(name);
		manage.restoreXml(parser, vectorFactory);
		if (!parser.peek().isStart()) {
			return;
		}
		parser.start("md5");
		String md5string = parser.end().getText();

		ExecutableRecord exe = manage.findExecutable(md5string);
		for (FunctionEntry entry : qchild.functionKeys) {
			correspond.add(manage.findFunction(entry.funcName, entry.spaceid, entry.address, exe));
		}
		parser.end();
	}

}
