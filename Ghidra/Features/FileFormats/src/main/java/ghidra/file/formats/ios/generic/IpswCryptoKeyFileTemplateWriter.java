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
package ghidra.file.formats.ios.generic;

import generic.jar.ResourceFile;
import ghidra.file.crypto.CryptoKeyFactory;

import java.io.*;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Reads an IPSW file and creates a template
 * XML file for storing the crypto keys and IVs.
 */
public final class IpswCryptoKeyFileTemplateWriter {
	private ZipFile ipswZipFile;

	/**
	 * Constructs a new template using the given IPSW file.
	 * @param ipswZipFile the IPSW file
	 */
	public IpswCryptoKeyFileTemplateWriter(ZipFile ipswZipFile) {
		this.ipswZipFile = ipswZipFile;
	}

	/**
	 * Returns TRUE if the XML file already exists.
	 * @return TRUE if the XML file already exists
	 */
	public boolean exists() {
		File ipswFile = new File(ipswZipFile.getName());

		ResourceFile xmlFile =
			new ResourceFile(CryptoKeyFactory.getCryptoDirectory(), ipswFile.getName() + ".xml");

		return xmlFile.exists();
	}

	/**
	 * Write the XML file.
	 * WARNING: If a file already exists, it will be overwritten.
	 * @throws IOException if an I/O error occurs
	 */
	public void write() throws IOException {
		if (!ipswZipFile.getName().endsWith(".ipsw")) {
			throw new IOException("File is not an IPSW.");
		}

		File ipswFile = new File(ipswZipFile.getName());

		File xmlFile =
			new File(CryptoKeyFactory.getCryptoDirectory().getFile(true), ipswFile.getName() +
				".xml");

		PrintWriter writer = new PrintWriter(xmlFile);

		writer.println("<FIRMWARE NAME=\"" + ipswZipFile.getName() + "\">");
		try {
			Enumeration<? extends ZipEntry> entries = ipswZipFile.entries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();

				if (entry.isDirectory()) {
					continue;
				}

				writer.println("    <FILE PATH=\"/" + entry.getName() + "\">");
				writer.println("        <KEY></KEY>");
				writer.println("        <IV></IV>");
				writer.println("    </FILE>");
			}
			writer.println("</FIRMWARE>");
		}
		finally {
			writer.close();
		}
	}
}
