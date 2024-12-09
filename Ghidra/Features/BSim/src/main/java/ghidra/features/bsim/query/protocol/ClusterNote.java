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
import java.util.Map;

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class ClusterNote {
	private FunctionDescription func;
	private int setsize;				// Number of hits in cluster
	private double maxscore;			// Highest similarity
	private double signif;				// Significance of highest similarity
	
	public ClusterNote() {}				// For use with restoreXml
	
	public ClusterNote(FunctionDescription f,int ss,double ms,double sig) {
		func = f;
		setsize = ss;
		maxscore = ms;
		signif = sig;
	}
	
	public FunctionDescription getFunctionDescription() { return func; }
	
	public double getMaxSimilarity() { return maxscore; }
	public double getSignificance() { return signif; }
	
	public void saveXml(Writer write) throws IOException {
		StringBuilder buf = new StringBuilder();
		buf.append("<note");
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "id", func.getExecutableRecord().getXrefIndex());
		SpecXmlUtils.xmlEscapeAttribute(buf, "name", func.getFunctionName());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "spaceid", func.getSpaceID());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "addr", func.getAddress());
		buf.append(">\n");
		buf.append(" <setsize>").append(SpecXmlUtils.encodeSignedInteger(setsize)).append("</setsize>\n");
		buf.append(" <sim>").append(Double.toString(maxscore)).append("</sim>\n");
		buf.append(" <sig>").append(Double.toString(signif)).append("</sig>\n");
		buf.append("</note>\n");
		write.append(buf.toString());
	}
	
	public void restoreXml(XmlPullParser parser,DescriptionManager manage,Map<Integer,ExecutableRecord> xrefMap) throws LSHException {
		XmlElement el = parser.start("note");
		int id = SpecXmlUtils.decodeInt(el.getAttribute("id"));
		ExecutableRecord exe = xrefMap.get(id);
		int spaceid = SpecXmlUtils.decodeInt(el.getAttribute("spaceid"));
		long address = SpecXmlUtils.decodeLong(el.getAttribute("addr"));
		func = manage.findFunction(el.getAttribute("name"), spaceid, address, exe);
		parser.start("setsize");
		setsize = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("sim");
		maxscore = Double.parseDouble(parser.end().getText());
		parser.start("sig");
		signif = Double.parseDouble(parser.end().getText());
		parser.end();
	}
}
