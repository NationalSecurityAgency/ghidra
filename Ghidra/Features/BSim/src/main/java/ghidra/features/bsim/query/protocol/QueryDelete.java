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
import java.util.*;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.xml.XmlPullParser;

/**
 * Request that a specific list of executables be deleted from a BSim database
 *
 */
public class QueryDelete extends BSimQuery<ResponseDelete> {

	public List<ExeSpecifier> exelist;
	public ResponseDelete respdelete;

	public QueryDelete() {
		super("delete");
		exelist = new ArrayList<ExeSpecifier>();
	}

	public void addSpecifier(ExeSpecifier spec) {
		exelist.add(spec);
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = respdelete = new ResponseDelete();
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		Iterator<ExeSpecifier> iter = exelist.iterator();
		while (iter.hasNext()) {
			iter.next().saveXml(fwrite);
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		exelist = new ArrayList<ExeSpecifier>();
		parser.start(name);
		while (parser.peek().isStart()) {
			ExeSpecifier spec = new ExeSpecifier();
			exelist.add(spec);
			spec.restoreXml(parser);
		}
		parser.end();
	}
}
