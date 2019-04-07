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
package ghidra.util.xml;



import java.io.*;

import resources.ResourceManager;




/**
 * A class for creating XML files.
 */
public class XmlWriter {
	private PrintWriter writer;
	private int indentLevel;
	private boolean incompleteLine;
	private boolean addedText;
	private Counter counter;

	/**
	 * Constructs a new XML writer.
	 * @param file the name of the output XML file
	 * @param dtdName the name of the DTD
	 * @throws IOException if an i/o error occurs
	 */
	public XmlWriter(File file, String dtdName) throws IOException {
	    this(new FileOutputStream(file), dtdName);
	}
	/**
	 * Constructs a new XML writer.
	 * @param out the output stream 
	 * @param dtdName the name of the DTD
	 * @throws IOException if an i/o error occurs
	 */
    public XmlWriter(OutputStream out, String dtdName) throws IOException {
        writer = new PrintWriter(out);
    	counter = new Counter();
		if (dtdName != null) {
			writeDTD(dtdName);
		}
    }
    /**
     * Returns the XML summary string.
     * @return the XML summary string
     */
	public Counter getCounter() {
		return counter;
	}
	/**
	 * Closes this XML writer.
	 */
	public void close() {
		writer.close();
	}
	/**
	 * Writes the specified DTD into the file.
	 * @param dtdName the name of the DTD
	 * @throws IOException  if an i/o error occurs
	 */
    public void writeDTD(String dtdName) throws IOException {
    	InputStream is = ResourceManager.getResourceAsStream(dtdName);
    	BufferedReader reader = new BufferedReader(new InputStreamReader(is));
    	String line;
    	while((line = reader.readLine()) != null) {
    		writer.println(line);
    	}
    	reader.close();
    }
    /**
     * Writes the specified start element.
     * @param name the name of the start element
     */
	public void startElement(String name) {
		startElement(name, null, null);
	}
    /**
     * Writes the specified start element with the attributes.
     * @param name the name of the start element
     * @param attrs the attributes of the start element
     */
	public void startElement(String name, XmlAttributes attrs) {
		startElement(name, attrs, null);
	}

    private void startElement(String name, XmlAttributes attrs, String text) {
    	if (addedText) {
    		throw new IllegalStateException("Cannot have child elements in parent elements with text!");
    	}

		counter.increment(name);

		if (incompleteLine) {
			writer.println(">");
			incompleteLine = false;
		}
    	indent();
    	indentLevel++;
    	writer.print("<");
    	writer.print(name);
		incompleteLine = true;
    	if (attrs != null) {
    		writer.print(attrs.toString());
    	}
    	if (text != null) {
    		writer.print(">");
    		writer.print(XmlUtilities.escapeElementEntities(text));
			incompleteLine = false;
			addedText = true;
    	}
    }

    /**
     * Writes the specified end element.
     * @param name the name of the end element
     */
    public void endElement(String name) {
		indentLevel--;
    	if (incompleteLine) {
			writer.println(" />");
    	}
    	else {
    		if (!addedText) {
				indent();
    		}
			writer.println("</"+name+">");
    	}
		incompleteLine = false;
		addedText = false;
    }
    /**
     * Writes the specified element with the attributes.
     * @param name the name of the start element
     * @param attrs the attributes of the start element
     */
	public void writeElement(String name, XmlAttributes attrs) {
		writeElement(name, attrs, null);
	}
    /**
     * Writes the specified element with the attributes and text.
     * @param name the name of the element
     * @param attrs the attributes of the element
     * @param text the text of the element
     */
	public void writeElement(String name, XmlAttributes attrs, String text) {
		startElement(name, attrs, text);
		endElement(name);
	}

	private void indent() {
		for (int i = 0; i < indentLevel; i++) {
			writer.print("    ");
		}
	}
}


