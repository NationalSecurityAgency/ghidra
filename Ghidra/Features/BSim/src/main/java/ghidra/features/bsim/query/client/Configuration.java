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
package ghidra.features.bsim.query.client;

import java.io.*;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import generic.lsh.vector.IDFLookup;
import generic.lsh.vector.WeightFactory;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public class Configuration {
	public DatabaseInformation info;
	public int k;						// Number of bits in a bin id
	public int L;						// Number of separate binnings
	public WeightFactory weightfactory;
	public IDFLookup idflookup;
	
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.write("<dbconfig>\n");
		info.saveXml(fwrite);
		StringBuffer buf = new StringBuffer();
		buf.append("<k>").append(k).append("</k>\n");
		buf.append("<L>").append(L).append("</L>\n");
		fwrite.write(buf.toString());
		weightfactory.saveXml(fwrite);
		idflookup.saveXml(fwrite);
		fwrite.write("</dbconfig>\n");
	}
	
	public void restoreXml(XmlPullParser parser) {
		parser.start("dbconfig");
		info = new DatabaseInformation();
		info.restoreXml(parser);
		parser.start("k");
		k = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("L");
		L = SpecXmlUtils.decodeInt(parser.end().getText());
		weightfactory = new WeightFactory();
		weightfactory.restoreXml(parser);
		idflookup = new IDFLookup();
		idflookup.restoreXml(parser);
		parser.end();
	}
	
	public void loadTemplate(ResourceFile rootPath, String filename)
			throws SAXException, IOException {
		ResourceFile file = new ResourceFile(rootPath, filename + ".xml");
		if (!file.exists()) {
			throw new FileNotFoundException("Unable to find configuration template");
		}
		ErrorHandler handler = SpecXmlUtils.getXmlHandler();
		XmlPullParser parser =
			new NonThreadedXmlPullParserImpl(file.getInputStream(), file.getName(), handler, false);
		parser.start("dbconfig");
		info = new DatabaseInformation();
		info.restoreXml(parser);
		parser.start("k");
		k = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("L");
		L = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("weightsfile");
		String weightsfile = parser.end().getText();
		parser.end();
		weightfactory = new WeightFactory();
		idflookup = new IDFLookup();
		
		if (weightsfile.equals("default")) {
			return;								// Use the default weights
		}
		file = new ResourceFile(rootPath, weightsfile);
		if (!file.exists()) {
			throw new FileNotFoundException("Unable to find weights file: "+weightsfile);
		}
		parser =
			new NonThreadedXmlPullParserImpl(file.getInputStream(), file.getName(), handler, false);
		parser.start("weights");
		weightfactory.restoreXml(parser);
		idflookup.restoreXml(parser);
		parser.end();
	}
}
