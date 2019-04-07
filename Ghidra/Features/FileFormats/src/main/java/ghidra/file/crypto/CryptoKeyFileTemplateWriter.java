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
package ghidra.file.crypto;

import generic.jar.ResourceFile;

import java.io.*;

/**
 * Reads a file and creates a template
 * XML file for storing the crypto keys and IVs.
 */
public final class CryptoKeyFileTemplateWriter {
	private String fileName;
	private PrintWriter writer;

	/**
	 * Constructs a new template using the given file name.
	 * @param fileName the name of the firmware file
	 */
	public CryptoKeyFileTemplateWriter(String fileName) {
		this.fileName = fileName;
	}

	/**
	 * Returns TRUE if the XML file already exists.
	 * @return TRUE if the XML file already exists
	 */
	public boolean exists() {
		ResourceFile xmlFile =
			new ResourceFile(CryptoKeyFactory.getCryptoDirectory(), fileName + ".xml");
		return xmlFile.exists();
	}

	/**
	 * Opens the crypto key file.
	 * WARNING: If a file already exists, it will be overwritten.
	 * @throws IOException if an I/O error occurs
	 */
	public void open() throws IOException {
		File xmlFile =
			new ResourceFile(CryptoKeyFactory.getCryptoDirectory(), fileName + ".xml").getFile(false);
		writer = new PrintWriter(xmlFile);
		writer.println("<FIRMWARE NAME=\"" + fileName + "\">");
	}

	/**
	 * Closes the crypto key file.
	 * @throws IOException if an I/O error occurs
	 */
	public void close() throws IOException {
		writer.println("</FIRMWARE>");
		writer.close();
	}

	/**
	 * Write the entryName to the XML file.
	 * @param entryName the name of the entry
	 * @throws IOException if an I/O error occurs
	 */
	public void write(String entryName) throws IOException {
		writer.println("    <FILE PATH=\"" + entryName + "\">");
		writer.println("        <KEY></KEY>");
		writer.println("        <IV></IV>");
		writer.println("    </FILE>");
	}
}
