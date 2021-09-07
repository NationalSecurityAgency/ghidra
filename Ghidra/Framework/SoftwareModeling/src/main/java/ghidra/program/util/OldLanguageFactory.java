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
package ghidra.program.util;

import java.io.*;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.output.XMLOutputter;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.xml.GenericXMLOutputter;

public class OldLanguageFactory {
	static final Logger log = LogManager.getLogger(OldLanguageFactory.class);

	public static final String OLD_LANGUAGE_FILE_EXT = ".lang";

	private HashMap<LanguageTag, OldLanguage> languageMap = new HashMap<LanguageTag, OldLanguage>();
	private HashMap<LanguageID, OldLanguage> latestVersionMap =
		new HashMap<LanguageID, OldLanguage>();
	private static OldLanguageFactory oldLanguageFactory;
	private int badFileCount = 0;

	/**
	 * Returns the single instance of the OldLanguageFactory.
	 */
	public static OldLanguageFactory getOldLanguageFactory() {
		if (oldLanguageFactory == null) {
			oldLanguageFactory = new OldLanguageFactory();
		}
		return oldLanguageFactory;
	}

	private OldLanguageFactory() {
		initLanguageMap();
	}

	/**
	 * Return old language if an old language specification file exists for the specified language and version.
	 * @param languageID
	 * @param majorVersion language major version, or -1 for latest version
	 * @return old language or null if specification not found.
	 */
	public Language getOldLanguage(LanguageID languageID, int majorVersion) {
		OldLanguage oldLang = languageMap.get(new LanguageTag(languageID, majorVersion));
		if (oldLang != null) {
			try {
				oldLang.validate();
				return oldLang;
			}
			catch (Exception e) {
				Msg.error(log, e.getMessage());
			}
		}
		return null;
	}

	/**
	 * Return language description for the latest version of an old language
	 * @param languageID
	 * @return old language description or null if specification not found.
	 */
	public LanguageDescription getLatestOldLanguage(LanguageID languageID) {
		OldLanguage oldLang = latestVersionMap.get(languageID);
		if (oldLang != null) {
			return oldLang.getDescription();
		}
		return null;
	}

	/**
	 * Return the Language Descriptions for the latest version of all old languages.
	 */
	public LanguageDescription[] getLatestOldLanaguageDescriptions() {
		LanguageDescription[] descriptions = new LanguageDescription[latestVersionMap.size()];
		int index = 0;
		for (OldLanguage oldLang : latestVersionMap.values()) {
			descriptions[index++] = oldLang.getDescription();
		}
		return descriptions;
	}

	/**
	 * Returns number of files which failed to parse properly.
	 * This only reflects minimal parsing of old language files
	 * which will prevent them from being added to old language map.
	 * This is intended to be used by a unit test.
	 */
	int badFileCount() {
		return badFileCount;
	}

	/**
	 * Validate all old language definitions contained within the old language map.  
	 * This is intended to be used by a unit test.
	 * @return number of validation errors
	 */
	int validateAllOldLanguages() {
		int errorCnt = 0;
		for (OldLanguage oldLang : languageMap.values()) {
			try {
				oldLang.validate();
			}
			catch (Exception e) {
				Msg.error(log, "Failed to validate old language: " + oldLang.getDescription() +
					" (Version " + oldLang.getVersion() + ")", e);
				++errorCnt;
			}
		}
		return errorCnt;
	}

	private void initLanguageMap() {
		LanguageService langSvc = DefaultLanguageService.getLanguageService();
		List<OldLanguage> oldLanguages = new ArrayList<OldLanguage>();
		getOldLanguages(oldLanguages);
		for (OldLanguage oldLang : oldLanguages) {
			LanguageDescription oldDescr = oldLang.getDescription();
			try {
				LanguageDescription curDescr =
					langSvc.getLanguageDescription(oldLang.getLanguageID());
				if (curDescr.getVersion() <= oldDescr.getVersion()) {
					// Ignore old versions which are inappropriate
					log.warn(
						"WARNING! Ignoring old language spec, version still exists: " + oldLang);
					continue;
				}
			}
			catch (LanguageNotFoundException e) {
			}
			LanguageTag tag = new LanguageTag(oldLang.getLanguageID(), oldLang.getVersion());
			languageMap.put(tag, oldLang);
			OldLanguage latest = latestVersionMap.get(oldLang.getLanguageID());
			if (latest == null || latest.getVersion() < oldLang.getVersion()) {
				latestVersionMap.put(oldLang.getLanguageID(), oldLang);
			}
		}
	}

	private void getOldLanguages(List<OldLanguage> list) {
		Iterable<ResourceFile> files =
			Application.findFilesByExtensionInApplication(OLD_LANGUAGE_FILE_EXT);
		for (ResourceFile file : files) {
			try {
				list.add(new OldLanguage(file));
			}
			catch (Exception e) {
				++badFileCount;
				Msg.error(log, "Failed to parse: " + file, e);
			}
		}
	}

	private static class LanguageTag {
		LanguageID id;
		int version;

		LanguageTag(LanguageID id, int version) {
			this.id = id;
			this.version = version;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof LanguageTag)) {
				return false;
			}
			LanguageTag other = (LanguageTag) obj;
			return version == other.version && id.equals(other.id);
		}

		@Override
		public int hashCode() {
			return id.hashCode() + version;
		}
	}

	//
	// Old Language File Generation Code
	//

	/**
	 * Create old-language file for the specified language.
	 * @param lang language
	 * @param file output file
	 * @throws IOException if file error occurs
	 * @throws LanguageNotFoundException if lang is unknown to DefaultLanguageService
	 */
	public static void createOldLanguageFile(Language lang, File file)
			throws IOException, LanguageNotFoundException {

		LanguageService languageService = DefaultLanguageService.getLanguageService();
		if (lang instanceof OldLanguage) {
			throw new LanguageNotFoundException(
				"Can't create an Old Langauge file from an OldLanguage");
		}
		LanguageDescription languageDescription =
			languageService.getLanguageDescription(lang.getLanguageID());
		Element root = new Element("language");
		root.setAttribute("version", Integer.toString(lang.getVersion()));
		root.setAttribute("endian", lang.isBigEndian() ? "big" : "little");
		root.addContent(getDescriptionElement(languageDescription));

		for (CompilerSpecDescription cs : lang.getCompatibleCompilerSpecDescriptions()) {
			Element compilerElement = new Element("compiler");
			compilerElement.setAttribute("name", cs.getCompilerSpecName());
			compilerElement.setAttribute("id", cs.getCompilerSpecID().getIdAsString());
			root.addContent(compilerElement);
		}

		root.addContent(getSpacesElement(lang));
		root.addContent(getRegistersElement(lang));

		Document doc = new Document(root);
		FileOutputStream out = new FileOutputStream(file);
		XMLOutputter xml = new GenericXMLOutputter();
		xml.output(doc, out);
		out.close();
	}

	private static Element getDescriptionElement(LanguageDescription languageDescription) {
		Element descriptionElement = new Element("description");

		Element element = new Element("id");
		element.setText(languageDescription.getLanguageID().getIdAsString());
		descriptionElement.addContent(element);

		String str = languageDescription.getProcessor().toString();
		if (str != null) {
			element = new Element("processor");
			element.setText(str);
			descriptionElement.addContent(element);
		}

		str = languageDescription.getVariant();
		if (str != null) {
			element = new Element("variant");
			element.setText(str);
			descriptionElement.addContent(element);
		}

		element = new Element("size");
		element.setText(Integer.toString(languageDescription.getSize()));
		descriptionElement.addContent(element);

		return descriptionElement;
	}

	private static Element getRegistersElement(Language lang) {

		Register contextReg = lang.getContextBaseRegister();
		Element registersElement = new Element("registers");
		if (contextReg != Register.NO_CONTEXT) {
			Element ctxElement = getRegisterElement(contextReg);
			int contextBitLength = contextReg.getBitLength();
			for (Register bitReg : contextReg.getChildRegisters()) {
				Element fieldElement = new Element("field");
				fieldElement.setAttribute("name", bitReg.getName());
				int fieldBitLength = bitReg.getBitLength();
				int lsb = bitReg.getLeastSignificatBitInBaseRegister();
				int msb = lsb + fieldBitLength - 1;

				// Transpose bit numbering to agree with Sleigh context bit numbering
				lsb = contextBitLength - msb - 1;
				msb = lsb + fieldBitLength - 1;

				fieldElement.setAttribute("range", lsb + "," + msb);
				ctxElement.addContent(fieldElement);
			}
			registersElement.addContent(ctxElement);
		}
		for (Register reg : lang.getRegisters()) {
			if (!reg.getBaseRegister().isProcessorContext()) {
				Element regElement = getRegisterElement(reg);
				registersElement.addContent(regElement);
			}
		}
		return registersElement;
	}

	private static Element getRegisterElement(Register reg) {
		Element regElement =
			new Element(reg.isProcessorContext() ? "context_register" : "register");
		regElement.setAttribute("name", reg.getName());
		Address addr = reg.getAddress();
		if (addr.isRegisterAddress()) {
			regElement.setAttribute("offset", NumericUtilities.toHexString(addr.getOffset()));
		}
		else {
			regElement.setAttribute("address", addr.toString(true));
		}
		regElement.setAttribute("bitsize", Integer.toString(reg.getBitLength()));
		return regElement;
	}

	private static Element getSpacesElement(Language lang) {
		Element spacesElement = new Element("spaces");
		AddressFactory addrFactory = lang.getAddressFactory();
		AddressSpace defSpace = addrFactory.getDefaultAddressSpace();
		for (AddressSpace space : lang.getAddressFactory().getAllAddressSpaces()) {
			Element element;
			if (space instanceof SegmentedAddressSpace) {
				element = new Element("segmented_space");
				element.setAttribute("name", space.getName());
			}
			else {
				String type;
				switch (space.getType()) {
					case AddressSpace.TYPE_CODE:
						type = "code";
						break;
					case AddressSpace.TYPE_RAM:
						type = "ram";
						break;
					case AddressSpace.TYPE_REGISTER:
						type = "register";
						break;
					default:
						continue;
				}
				element = new Element("space");
				element.setAttribute("name", space.getName());
				element.setAttribute("type", type);
				element.setAttribute("size", Integer.toString(space.getSize() / 8));
				int wordsize = space.getAddressableUnitSize();
				if (wordsize != 1) {
					element.setAttribute("wordsize", Integer.toString(wordsize));
				}
			}

			//element.setAttribute("unique", Integer.toString(space.getUnique()));

			if (space == defSpace) {
				element.setAttribute("default", "yes");
			}
			spacesElement.addContent(element);
		}
		return spacesElement;
	}
}
