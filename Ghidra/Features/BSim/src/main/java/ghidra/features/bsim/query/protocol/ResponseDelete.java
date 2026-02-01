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
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Response to a QueryDelete request containing a listing of the md5's of successfully deleted executables and
 * a count of their functions. If a requested executable could not be deleted for some reason it is listed in
 * a separate -missedlist-
 *
 */
public class ResponseDelete extends QueryResponseRecord {

	public static class DeleteResult {
		public String md5;		// Md5 of executable successfully deleted
		public String name;		// name of deleted executable
		public int funccount;	// Number of (now deleted) function records associated with executable

		public void saveXml(Writer fwrite) throws IOException {
			fwrite.append("<delrec>\n");
			fwrite.append(" <md5>").append(md5).append("</md5>\n");
			fwrite.append(" <name>");
			SpecXmlUtils.xmlEscapeWriter(fwrite, name);
			fwrite.append("</name>\n");
			fwrite.append(" <count>")
				.append(SpecXmlUtils.encodeSignedInteger(funccount))
				.append("</count>\n");
			fwrite.append("</delrec>\n");
		}

		public void restoreXml(XmlPullParser parser) {
			parser.start("delrec");
			parser.start("md5");
			md5 = parser.end().getText();
			parser.start("name");
			name = parser.end().getText();
			parser.start("count");
			funccount = SpecXmlUtils.decodeInt(parser.end().getText());
			parser.end();
		}
	}

	public List<DeleteResult> reslist;		// List of executables successfully deleted
	public List<ExeSpecifier> missedlist;		// List of executables that could not be deleted

	public ResponseDelete() {
		super("responsedelete");
		reslist = new ArrayList<DeleteResult>();
		missedlist = new ArrayList<ExeSpecifier>();
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		Iterator<DeleteResult> iter = reslist.iterator();
		while (iter.hasNext()) {
			iter.next().saveXml(fwrite);
		}
		Iterator<ExeSpecifier> miter = missedlist.iterator();
		while (miter.hasNext()) {
			miter.next().saveXml(fwrite);
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		reslist = new ArrayList<DeleteResult>();
		missedlist = new ArrayList<ExeSpecifier>();
		parser.start(name);
		while (parser.peek().isStart()) {
			XmlElement el = parser.peek();
			if (el.getName().equals("delrec")) {
				DeleteResult res = new DeleteResult();
				res.restoreXml(parser);
				reslist.add(res);
			}
			else {
				ExeSpecifier spec = new ExeSpecifier();
				spec.restoreXml(parser);
			}
		}
		parser.end();
	}

}
