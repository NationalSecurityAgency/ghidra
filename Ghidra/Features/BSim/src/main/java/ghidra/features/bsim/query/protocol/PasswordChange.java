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
 * Request a password change for a specific user
 *   Currently provides no explicit protection for password data on the client.
 *   Should be used in conjunction with connection encryption (SSL) to protect
 *   data in transit to the server.
 */
public class PasswordChange extends BSimQuery<ResponsePassword> {

	public ResponsePassword passwordResponse;
	public String username;				// Identifier for user whose password should be changed
	public char[] newPassword;			// The new password as raw character data

	public PasswordChange() {
		super("passwordchange");
		username = null;
		newPassword = null;
	}

	/**
	 * Clear the password data.  (Should be) used by database client immediately upon sending request to server
	 */
	public void clearPassword() {
		if (newPassword != null) {
			for (int i = 0; i < newPassword.length; ++i) {
				newPassword[i] = ' ';
			}
		}
	}

	@Override
	public void buildResponseTemplate() {
		if (response == null) {
			response = passwordResponse = new ResponsePassword();
		}
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<").append(name);
		fwrite.append(" username=\"").append(username);
		fwrite.append("\">");
		SpecXmlUtils.xmlEscapeWriter(fwrite, new String(newPassword));
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		XmlElement el = parser.start(name);
		username = el.getAttribute("username");
		newPassword = parser.end().getText().toCharArray();
	}

}
