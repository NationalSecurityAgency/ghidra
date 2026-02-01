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
 * Query for a single function in a single executable by giving either the md5 of the executable, or its name
 * and version. Then give the name of the function.  If the name of the function is empty, this query
 * returns all functions in the executable
 *
 */
public class QueryName extends BSimQuery<ResponseName> {

	public ExeSpecifier spec;
	public String funcname = "";
	public ResponseName nameresponse = null;
	public int maxfunc;					// Maximum function records to return
	public boolean printselfsig;
	public boolean printjustexe;
	public boolean fillinSigs;
	public boolean fillinCallgraph;
	public boolean fillinCategories;

	public QueryName() {
		super("queryname");
		spec = new ExeSpecifier();
		maxfunc = 1000;
		printselfsig = false;
		printjustexe = false;
		fillinSigs = true;
		fillinCallgraph = false;
		fillinCategories = true;
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = nameresponse = new ResponseName();
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		spec.saveXml(fwrite);
		fwrite.append("<funcname>");
		if (funcname != null)
			SpecXmlUtils.xmlEscapeWriter(fwrite, funcname);
		fwrite.append("</funcname>\n");
		fwrite.append("<maxfunc>");
		fwrite.append(Integer.toString(maxfunc));
		fwrite.append("</maxfunc>\n");
		if (printselfsig)
			fwrite.append("<printselfsig>true</printselfsig>\n");
		else
			fwrite.append("<printselfsig>false</printselfsig>\n");
		if (printjustexe)
			fwrite.append("<printjustexe>true</printjustexe>\n");
		else
			fwrite.append("<printjustexe>false</printjustexe>\n");
		if (fillinSigs)
			fwrite.append("<sigs>true</sigs>\n");
		else
			fwrite.append("<sigs>false</sigs>\n");
		if (fillinCallgraph)
			fwrite.append("<callgraph>true</callgraph>\n");
		else
			fwrite.append("<callgraph>false</callgraph>\n");
		if (fillinCategories)
			fwrite.append("<categories>true</categories>\n");
		else
			fwrite.append("<categories>false</categories>\n");
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		parser.start(name);
		spec = new ExeSpecifier();
		spec.restoreXml(parser);
		parser.start("funcname");
		funcname = parser.end().getText();
		parser.start("maxfunc");
		maxfunc = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("printselfsig");
		printselfsig = SpecXmlUtils.decodeBoolean(parser.end().getText());
		parser.start("printjustexe");
		printjustexe = SpecXmlUtils.decodeBoolean(parser.end().getText());
		parser.start("sigs");
		fillinSigs = SpecXmlUtils.decodeBoolean(parser.end().getText());
		parser.start("callgraph");
		fillinCallgraph = SpecXmlUtils.decodeBoolean(parser.end().getText());
		parser.start("categories");
		fillinCategories = SpecXmlUtils.decodeBoolean(parser.end().getText());
		parser.end();
	}

}
