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
import ghidra.features.bsim.query.description.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Response to a QueryUpdate request to a BSim database.  Simple counts of successful updates are given.
 * References to any original ExecutableRecord or FunctionDescription objects that could not be updated
 * are also returned. 
 *
 */
public class ResponseUpdate extends QueryResponseRecord {

	public List<ExecutableRecord> badexe;
	public List<FunctionDescription> badfunc;
	public int exeupdate;				// Number of executable records updated
	public int funcupdate;				// Number of function records updated
	public QueryUpdate qupdate;			// Original query

	public ResponseUpdate(QueryUpdate q) {
		super("responseupdate");
		badexe = new ArrayList<ExecutableRecord>();
		badfunc = new ArrayList<FunctionDescription>();
		exeupdate = 0;
		funcupdate = 0;
		qupdate = q;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		qupdate.manage.populateExecutableXref();	// Make sure cross-references are pregenerated
		fwrite.append('<').append(name).append(">\n");
		Iterator<ExecutableRecord> iter2 = badexe.iterator();
		while (iter2.hasNext()) {
			ExecutableRecord exe = iter2.next();
			fwrite.append("<badexe id=\"");
			fwrite.append(SpecXmlUtils.encodeUnsignedInteger(exe.getXrefIndex()));
			fwrite.append("\">\n");
		}
		Iterator<FunctionDescription> iter = badfunc.iterator();
		while (iter.hasNext()) {
			FunctionDescription func = iter.next();
			fwrite.append("<badfunc id=\"");
			fwrite.append(
				SpecXmlUtils.encodeUnsignedInteger(func.getExecutableRecord().getXrefIndex()));
			fwrite.append("\" name=\"");
			SpecXmlUtils.xmlEscapeWriter(fwrite, func.getFunctionName());
			fwrite.append("\" spaceid=\"");
			fwrite.append(SpecXmlUtils.encodeSignedInteger(func.getSpaceID()));
			fwrite.append("\" addr=\"");
			fwrite.append(SpecXmlUtils.encodeUnsignedInteger(func.getAddress()));
			fwrite.append("\">\n");
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {

		DescriptionManager manage = qupdate.manage;
		Map<Integer, ExecutableRecord> exeMap = manage.generateExecutableXrefMap();
		parser.start();
		while (parser.peek().isStart()) {
			XmlElement el = parser.start();
			if (el.getName().equals("badexe")) {
				int id = SpecXmlUtils.decodeInt(el.getAttribute("id"));
				ExecutableRecord exe = exeMap.get(id);
				badexe.add(exe);
			}
			else if (el.getName().equals("badfunc")) {
				int id = SpecXmlUtils.decodeInt(el.getAttribute("id"));
				int spaceid = SpecXmlUtils.decodeInt(el.getAttribute("spaceid"));
				long address = SpecXmlUtils.decodeLong(el.getAttribute("addr"));
				ExecutableRecord exe = exeMap.get(id);
				FunctionDescription func =
					manage.findFunction(el.getAttribute("name"), spaceid, address, exe);
				badfunc.add(func);
			}
			parser.end();
		}
	}

}
