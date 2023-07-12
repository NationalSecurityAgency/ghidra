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
package ghidra.framework.options;

import java.io.File;
import java.io.IOException;

import org.jdom.Element;

import ghidra.util.xml.XmlUtilities;
import utilities.util.FileUtilities;

/**
 * A convenience class for creating a GProperties object from a file containing XML data
 * generated from {@link GProperties#saveToXmlFile(File)}
 */
public class XmlProperties extends GProperties {

	public XmlProperties(File file) throws IOException {
		super(getXmlElement(file));
	}

	public XmlProperties(Element element) {
		super(element);
	}

	protected XmlProperties(String name) {
		super(name);
	}

	private static Element getXmlElement(File file) throws IOException {
		byte[] bytes = FileUtilities.getBytesFromFile(file);
		return XmlUtilities.byteArrayToXml(bytes);
	}

}
