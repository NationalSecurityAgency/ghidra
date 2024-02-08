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
 *  Response of server indicating whether a password change request ({@link PasswordChange}) succeeded
 */
public class ResponsePassword extends QueryResponseRecord {

	public boolean changeSuccessful;		// true if the password change was successful
	public String errorMessage;				// Error message if change was not successful

	public ResponsePassword() {
		super("responsepassword");
		changeSuccessful = false;
		errorMessage = null;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name);
		fwrite.append(" success=\"");
		SpecXmlUtils.encodeBoolean(changeSuccessful);
		fwrite.append("\">");
		if (errorMessage != null) {
			SpecXmlUtils.xmlEscapeWriter(fwrite, errorMessage);
		}
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		XmlElement el = parser.start(name);
		changeSuccessful = SpecXmlUtils.decodeBoolean(el.getAttribute("success"));
		errorMessage = parser.end().getText();
		if (errorMessage != null && errorMessage.length() == 0) {
			errorMessage = null;
		}
	}

}
