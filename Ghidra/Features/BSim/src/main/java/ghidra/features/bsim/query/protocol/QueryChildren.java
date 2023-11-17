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
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Query based on a single executable and a specific list of functions names within the executable
 * The response will be the corresponding FunctionDescription records and a record for each child
 * of the specified functions
 *
 */
public class QueryChildren extends BSimQuery<ResponseChildren> {

	public String md5sum = null;
	public String name_exec = null;
	public String arch = null;
	public String name_compiler = null;
	public List<FunctionEntry> functionKeys;
	public ResponseChildren childrenresponse = null;

	public QueryChildren() {
		super("querychildren");
		functionKeys = new ArrayList<FunctionEntry>();
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null) {
			response = childrenresponse = new ResponseChildren(this);
		}
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		if ((md5sum != null) && (md5sum.length() != 0)) {
			fwrite.append("  <md5>").append(md5sum).append("</md5>\n");
		}
		else {
			fwrite.append("  <name>");
			if (name_exec != null) {
				SpecXmlUtils.xmlEscapeWriter(fwrite, name_exec);
			}
			fwrite.append("</name>\n");
			fwrite.append("  <arch>");
			if (arch != null) {
				SpecXmlUtils.xmlEscapeWriter(fwrite, arch);
			}
			fwrite.append("</arch>\n");
			fwrite.append("  <compiler>");
			if (name_compiler != null) {
				SpecXmlUtils.xmlEscapeWriter(fwrite, name_compiler);
			}
			fwrite.append("</compiler>\n");
		}
		for (int i = 0; i < functionKeys.size(); ++i) {
			functionKeys.get(i).saveXml(fwrite);
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		parser.start(name);
		XmlElement el = parser.start();
		if (el.getName().equals("md5")) {
			md5sum = parser.end().getText();
			name_exec = null;
			arch = null;
			name_compiler = null;
		}
		else {
			md5sum = null;
			name_exec = parser.end().getText();
			parser.start("arch");
			arch = parser.end().getText();
			parser.start("compiler");
			name_compiler = parser.end().getText();
		}
		while (parser.peek().isStart()) {
			FunctionEntry functionKey = FunctionEntry.restoreXml(parser);
			functionKeys.add(functionKey);
		}
		parser.end();
	}

}
