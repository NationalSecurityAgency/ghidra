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

import java.io.*;
import java.util.*;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CryptoException;
import ghidra.util.xml.XmlUtilities;
import util.CollectionUtils;

public final class CryptoKeyFactory {

	private static Map<String, Map<String, CryptoKey>> cryptoMap =
		new HashMap<String, Map<String, CryptoKey>>();

	private static Map<String, Long> fileDatesMap = new HashMap<String, Long>();

	public static void forceReload() {
		cryptoMap.clear();
		fileDatesMap.clear();
		loadIfNeeded();
	}

	/**
	 * Loads the crypto key XML file if it is not currently loaded OR if it has
	 * changed since it was last loaded.
	 */
	private static void loadIfNeeded() {
		ResourceFile cryptoDirectory = getCryptoDirectory();

		ResourceFile[] files = cryptoDirectory.listFiles();
		for (ResourceFile file : files) {
			if (!file.getName().endsWith(".xml")) {
				continue;
			}
			if (fileDatesMap.containsKey(file.getName())) {
				if (fileDatesMap.get(file.getName()) == file.lastModified()) {
					continue;
				}
			}
			fileDatesMap.put(file.getName(), file.lastModified());
			try {
				InputStream is = file.getInputStream();
				try {
					SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
					Document doc = sax.build(is);
					Element root = doc.getRootElement();
					String firmwareName = root.getAttributeValue("NAME");
					if (!cryptoMap.containsKey(firmwareName)) {
						cryptoMap.put(firmwareName, new HashMap<String, CryptoKey>());
					}
					List<Element> firmwareFileList =
						CollectionUtils.asList(root.getChildren(), Element.class);
					Iterator<Element> firmwareFileIter = firmwareFileList.iterator();
					while (firmwareFileIter.hasNext()) {
						Element firmwareFileElement = firmwareFileIter.next();
						String path = firmwareFileElement.getAttributeValue("PATH");
						if (firmwareFileElement.getAttribute("not_encrypted") != null) {
							cryptoMap.get(firmwareName).put(path, CryptoKey.NOT_ENCRYPTED_KEY);
						}
						else {
							Element keyElement = firmwareFileElement.getChild("KEY");
							String keyString = keyElement.getText().trim();
							if ((keyString.length() % 2) != 0) {
								throw new CryptoException("Invalid key length in [" + firmwareName +
									".xml] for [" + path + "]");
							}
							byte[] key = NumericUtilities.convertStringToBytes(keyString);
							Element ivElement = firmwareFileElement.getChild("IV");
							String ivString = ivElement.getText().trim();
							if ((ivString.length() % 2) != 0) {
								throw new CryptoException("Invalid iv length in [" + firmwareName +
									".xml] for [" + path + "]");
							}
							byte[] iv = NumericUtilities.convertStringToBytes(ivString);
							CryptoKey cryptoKey = new CryptoKey(key, iv);
							cryptoMap.get(firmwareName).put(path, cryptoKey);
						}
					}
				}
				finally {
					is.close();
				}
			}
			catch (Exception e) {
				Msg.showError(CryptoKeyFactory.class, null, "Error Parsing Crypto Keys File",
					"Unable to process crypto keys files.", e);
			}
		}
	}

	public static ResourceFile getCryptoDirectory() {
		try {
			return Application.getModuleDataSubDirectory("crypto");
		}
		catch (IOException e) {
		}
		throw new RuntimeException("cannot find crypto directory");
	}

	public static CryptoKey getCryptoKey(String firmwareName, String firmwarePath)
			throws CryptoException {

		loadIfNeeded();

		Map<String, CryptoKey> firmwareMap = cryptoMap.get(firmwareName);
		if (firmwareMap == null) {
			throw new CryptoException(
				"Firmware may be encrypted, but XML key file does not exist: " + "[" +
					firmwareName + ".xml]");
		}

		CryptoKey cryptoKey = firmwareMap.get(firmwarePath);//check for absolute path

		if (cryptoKey == null) {//check for relative path
			File file = new File(firmwarePath);
			cryptoKey = firmwareMap.get(file.getName());
		}
		if (cryptoKey == null) {//okay it does not exist
			throw new CryptoException("[" + firmwareName + ".xml]" +
				" does not contain an entry for " + firmwarePath + ".  File might be encrypted.");
		}
		if (cryptoKey == CryptoKey.NOT_ENCRYPTED_KEY) {
			return cryptoKey;
		}
		if (cryptoKey.isEmpty()) {
			throw new CryptoException(
				"No key specified in [" + firmwareName + ".xml] file for [" + firmwarePath + "]");
		}
		return cryptoKey;
	}

}
