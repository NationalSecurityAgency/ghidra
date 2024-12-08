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
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Response to an AdjustVectorIndex request, returning a boolean value of either success or failure of the request
 *
 */
public class ResponseAdjustIndex extends QueryResponseRecord {

	public boolean success;
	public boolean operationSupported;		// true if the back-end supports this operation
	
	public ResponseAdjustIndex() {
		super("responseadjust");
		success = false;
		operationSupported = true;
	}
	
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(" success=\"");
		fwrite.append(SpecXmlUtils.encodeBoolean(success));
		fwrite.append("\" support=\"");
		fwrite.append(SpecXmlUtils.encodeBoolean(operationSupported));
		fwrite.append("\"/>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory) throws LSHException {
		XmlElement el = parser.start(name);
		success = SpecXmlUtils.decodeBoolean(el.getAttribute("success"));
		operationSupported = SpecXmlUtils.decodeBoolean(el.getAttribute("support"));
		parser.end();
	}

}
