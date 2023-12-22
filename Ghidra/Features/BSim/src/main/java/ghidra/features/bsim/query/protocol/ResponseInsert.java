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
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlPullParser;

/**
 * A simple response to an InsertRequest to a BSim database.
 * This object provides separate counts of executables successfully inserted and functions successfully inserted.
 *
 */
public class ResponseInsert extends QueryResponseRecord {

	public int numexe;			// Number of executables inserted
	public int numfunc;			// NUmber of functions inserted
	
	public ResponseInsert() {
		super("responseinsert");
	}
	
	@Override
	public void mergeResults(QueryResponseRecord subresponse) {
		ResponseInsert subinsert = (ResponseInsert)subresponse;
		numexe += subinsert.numexe;
		numfunc += subinsert.numfunc;
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		fwrite.append(" <numexe>").append(SpecXmlUtils.encodeSignedInteger(numexe)).append("</numexe>\n");
		fwrite.append(" <numfunc>").append(SpecXmlUtils.encodeSignedInteger(numfunc)).append("</numfunc>\n");
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		parser.start(name);
		parser.start("numexe");
		numexe = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("numfunc");
		numfunc = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.end();
	}

}
