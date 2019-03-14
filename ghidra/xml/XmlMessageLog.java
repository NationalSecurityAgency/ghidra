/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.xml;

import ghidra.app.util.importer.MessageLog;

/**
 * A sub-class of MessageLog to handle appending messages from the XML parser.
 * 
 */
public class XmlMessageLog extends MessageLog {
	private XmlPullParser parser;

	/**
	 * Constructs a new XML message log.
	 */
	public XmlMessageLog() {
		super();
	}

	/**
	 * Sets the XML parser.
	 * 
	 * @param parser
	 *            the XML parser
	 */
	public void setParser(XmlPullParser parser) {
		this.parser = parser;
	}

	/**
	 * @see ghidra.app.util.importer.MessageLog#appendMsg(java.lang.String)
	 */
	@Override
    public void appendMsg(String msg) {
		int lineNum = 0;
		if (parser != null) {
			lineNum = parser.getLineNumber();
		}
		if (lineNum > 0) {
			appendMsg(parser.getLineNumber(), msg);
		} else {
			super.appendMsg(msg);
		}
	}
}
