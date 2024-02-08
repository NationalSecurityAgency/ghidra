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
 * Request that the database preload portions of the main vector table so that initial queries return faster from
 * a server that has just been restarted.
 *
 */
public class PrewarmRequest extends BSimQuery<ResponsePrewarm> {

	public int mainIndexConfig;			// For the main index -- 0=don't load 1=load into RAM 2=load into cache
	public int secondaryIndexConfig;	// For the secondary index -- 0=don't load 1=load into RAM 2=load into cache
	public int vectorTableConfig;		// For vectors -- 0=don't load 1=load into RAM 2=load into cache
	public ResponsePrewarm prewarmresponse;

	public PrewarmRequest() {
		super("prewarmrequest");
		// Set up default configuration
		mainIndexConfig = 2;			// Load into cache
		secondaryIndexConfig = 1;		// Load into any extra RAM
		vectorTableConfig = 1;			// Load into any extra RAM
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null)
			response = prewarmresponse = new ResponsePrewarm();
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		StringBuffer buffer = new StringBuffer();
		buffer.append('<').append(name).append(">\n");
		buffer.append("<main>");
		SpecXmlUtils.encodeSignedInteger(mainIndexConfig);
		buffer.append("</main>\n");
		buffer.append("<secondary>");
		SpecXmlUtils.encodeSignedInteger(secondaryIndexConfig);
		buffer.append("</secondary>\n");
		buffer.append("<table>");
		SpecXmlUtils.encodeSignedInteger(vectorTableConfig);
		buffer.append("</table>\n");
		buffer.append("</").append(name).append(">\n");
		fwrite.write(buffer.toString());
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		parser.start(name);
		parser.start("main");
		mainIndexConfig = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("secondary");
		secondaryIndexConfig = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("table");
		vectorTableConfig = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.end();
	}

}
