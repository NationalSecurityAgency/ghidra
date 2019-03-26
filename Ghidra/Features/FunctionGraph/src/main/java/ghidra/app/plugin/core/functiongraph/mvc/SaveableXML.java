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
package ghidra.app.plugin.core.functiongraph.mvc;

import java.io.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import ghidra.util.*;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;

public class SaveableXML extends PrivateSaveable {

	private final Class<?>[] fields = new Class<?>[] { String.class };
	private Element element;

	public SaveableXML(Element element) {
		this.element = element;
	}

	public SaveableXML() {
		// for restoring
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return fields;
	}

	@Override
	public void save(ObjectStorage objStorage) {

		Document document = new Document(element);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		XMLOutputter xmlOutputter = new GenericXMLOutputter();

		try {
			xmlOutputter.output(document, outputStream);
		}
		catch (IOException ioe) {
			// shouldn't happen, as we are using our output stream
			Msg.error(getClass(), "Unable to save XML data.", ioe);
			return;
		}

		String xmlString = outputStream.toString();
		objStorage.putString(xmlString);
	}

	@Override
	public void restore(ObjectStorage objStorage) {

		String xmlString = objStorage.getString();
		StringReader reader = new StringReader(xmlString);
		SAXBuilder builder = XmlUtilities.createSecureSAXBuilder(false, false);

		try {
			element = builder.build(reader).getRootElement();
		}
		catch (JDOMException e) {
			Msg.error(getClass(), "Unable to read XML data.", e);
		}
		catch (IOException e) {
			// shouldn't happen, as we are using our own reader
			Msg.error(getClass(), "Unable to read XML data.", e);
		}

	}

	public Element getElement() {
		return element;
	}

	@Override
	public int getSchemaVersion() {
		return 0;
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion,
			ObjectStorage currentObjStorage) {
		return false;
	}
}
