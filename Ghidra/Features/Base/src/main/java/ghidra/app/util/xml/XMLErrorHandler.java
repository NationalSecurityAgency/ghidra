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
package ghidra.app.util.xml;

import org.xml.sax.*;

/**
 * An implemenation of the basic interface for SAX error handlers.
 * Per the documentation, this class is required to prevent the SAX
 * parser from squelching all parse exceptions.
 *
 *
 */
public class XMLErrorHandler implements ErrorHandler {
	@Override
	public void warning(SAXParseException exception) throws SAXException {
		String msg = "Warning on line " + exception.getLineNumber() + ": " + exception.getMessage();
		throw new SAXException(msg);
	}

	@Override
	public void error(SAXParseException exception) throws SAXException {
		String msg = "Error on line " + exception.getLineNumber() + ": " + exception.getMessage();
		throw new SAXException(msg);
	}

	@Override
	public void fatalError(SAXParseException exception) throws SAXException {
		String msg =
			"Fatal error on line " + exception.getLineNumber() + ": " + exception.getMessage();
		throw new SAXException(msg);
	}
}
