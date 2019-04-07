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
package ghidra.app.util.bin.format.dwarf4.next;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import generic.jar.ResourceFile;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

/**
 * Factory class to instantiate and cache {@link DWARFRegisterMappings} objects.
 * <p>
 */
public class DWARFRegisterMappingsManager {
	private static final String DWARF_REGISTER_MAPPING_NAME = "DWARF.register.mapping.file";

	private static Map<LanguageID, DWARFRegisterMappings> cache = new HashMap<>();

	/**
	 * Returns true if the specified {@link LanguageDescription} has DWARF
	 * register mappings.
	 *
	 * @param langDesc The {@link LanguageDescription} to test
	 * @return true if the language has a DWARF register mapping specified
	 * @throws IOException if there was an error in the language LDEF file.
	 */
	public static boolean hasDWARFRegisterMapping(LanguageDescription langDesc) throws IOException {
		return (langDesc instanceof SleighLanguageDescription) &&
			getDWARFRegisterMappingFileNameFromLangDesc(
				(SleighLanguageDescription) langDesc) != null;
	}

	/**
	 * Returns true if the specified {@link Language} has DWARF register
	 * mappings.
	 *
	 * @param lang The {@link Language} to test
	 * @return true if the language has a DWARF register mapping specified
	 * @throws IOException if there was an error in the language LDEF file.
	 */
	public static boolean hasDWARFRegisterMapping(Language lang) throws IOException {
		return hasDWARFRegisterMapping(lang.getLanguageDescription());
	}

	/**
	 * Returns a possibly cached {@link DWARFRegisterMappings} object for the
	 * specified language,
	 * <p>
	 * 
	 * @param lang {@link Language} to get the matching DWARF register mappings
	 *            for
	 * @return {@link DWARFRegisterMappings} instance, never null
	 * @throws IOException if mapping not found or invalid
	 */
	public static synchronized DWARFRegisterMappings getMappingForLang(Language lang)
			throws IOException {
		DWARFRegisterMappings result = cache.get(lang.getLanguageID());
		if (result == null) {
			result = readMappingForLang(lang);
			cache.put(lang.getLanguageID(), result);
		}
		return result;
	}

	/*
	 * Returns the DWARF register mapping file specified in the lang's definition, or
	 * null if it does not exist.
	 */
	private static String getDWARFRegisterMappingFileNameFromLangDesc(
			SleighLanguageDescription langDesc) throws IOException {
		List<String> dwarfSpecFilename = langDesc.getExternalNames(DWARF_REGISTER_MAPPING_NAME);
		if (dwarfSpecFilename == null) {
			return null;
		}
		if (dwarfSpecFilename.size() > 1) {
			throw new IOException("Multiple DWARF register mappings found for language " +
				langDesc.getLanguageID() + ": " + dwarfSpecFilename.toString());
		}
		return dwarfSpecFilename.get(0);
	}

	/**
	 * Returns {@link ResourceFile} that should contain the specified language's
	 * DWARF register mapping, never null.
	 *
	 * @param lang {@link Language} to find the mapping file for.
	 * @return {@link ResourceFile} of where the mapping file should be, never
	 *         null.
	 * @throws IOException if not a Sleigh language or no mapping specified or
	 *             multiple mappings specified.
	 */
	public static ResourceFile getDWARFRegisterMappingFileFor(Language lang) throws IOException {
		LanguageDescription langDesc = lang.getLanguageDescription();
		if (!(langDesc instanceof SleighLanguageDescription)) {
			throw new IOException("Not a Sleigh Language: " + lang.getLanguageID());
		}
		SleighLanguageDescription sld = (SleighLanguageDescription) langDesc;
		ResourceFile defsFile = sld.getDefsFile();
		ResourceFile parentFile = defsFile.getParentFile();
		String dwarfSpecFilename = getDWARFRegisterMappingFileNameFromLangDesc(sld);
		if (dwarfSpecFilename == null) {
			throw new IOException("No DWARF register mapping information found for language " +
				lang.getLanguageID().getIdAsString());
		}
		ResourceFile dwarfFile = new ResourceFile(parentFile, dwarfSpecFilename);

		return dwarfFile;
	}

	/**
	 * Finds the DWARF register mapping information file specified in the
	 * specified language's LDEF file and returns a new
	 * {@link DWARFRegisterMappings} object containing the data read from that
	 * file.
	 * <p>
	 * Throws {@link IOException} if the lang does not have a mapping or it is
	 * invalid.
	 * <p>
	 * 
	 * @param lang {@link Language} to read the matching DWARF register mappings
	 *            for
	 * @return a new {@link DWARFRegisterMappings} instance, created from
	 *         information read from the {@link #DWARF_REGISTER_MAPPING_NAME}
	 *         xml file referenced in the language's LDEF, never null.
	 * @throws IOException if there is no DWARF register mapping file associated
	 *             with the specified {@link Language} or if there was an error
	 *             in the register mapping data.
	 */
	public static DWARFRegisterMappings readMappingForLang(Language lang) throws IOException {
		ResourceFile dwarfFile = getDWARFRegisterMappingFileFor(lang);
		if (!dwarfFile.exists()) {
			throw new IOException("Missing DWARF register mapping file " + dwarfFile +
				" for language " + lang.getLanguageID().getIdAsString());
		}

		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		try (InputStream fis = dwarfFile.getInputStream()) {
			Document doc = sax.build(fis);
			Element rootElem = doc.getRootElement();
			return readMappingFrom(rootElem, lang);
		}
		catch (JDOMException | IOException e) {
			Msg.error(DWARFRegisterMappingsManager.class,
				"Bad DWARF register mapping file " + dwarfFile, e);
			throw new IOException("Failed to read DWARF register mapping file " + dwarfFile, e);
		}
	}

	/**
	 * Creates a new {@link DWARFRegisterMappings} from the data present in the
	 * xml element.
	 * <p>
	 * 
	 * @param rootElem JDom XML element containing the &lt;dwarf&gt; root
	 *            element of the mapping file.
	 * @param lang The Ghidra {@link Language} that the DWARF register mapping
	 *            applies to
	 * @return a new {@link DWARFRegisterMappings} instance, never null.
	 * @throws IOException if missing or invalid data found in xml
	 */
	public static DWARFRegisterMappings readMappingFrom(Element rootElem, Language lang)
			throws IOException {

		Element regMappingsElem = rootElem.getChild("register_mappings");
		if (regMappingsElem == null) {
			throw new IOException("Missing required DWARF <register_mappings> element");
		}

		Map<Integer, Register> regmap = new HashMap<>();
		int spi;
		long cfa;
		boolean useFPS;
		try {
			spi = readMappingsElem(regMappingsElem, lang, regmap);
			Element callFrameElem = rootElem.getChild("call_frame_cfa");
			cfa = (callFrameElem != null)
					? XmlUtilities.parseOptionalBoundedLongAttr(callFrameElem, "value", 0, 0,
						Long.MAX_VALUE)
					: 0;

			Element useFormalParameterStorageElem =
				rootElem.getChild("use_formal_parameter_storage");
			useFPS = (useFormalParameterStorageElem != null);
		}
		catch (NumberFormatException nfe) {
			throw new IOException("Failed to parse DWARF register mappings: " + nfe.getMessage(),
				nfe);
		}

		return new DWARFRegisterMappings(regmap, cfa, spi, useFPS);
	}

	/*
	 * Reads and populates map of dwarf reg numbers to ghidra register objects, and returns
	 * the index of the dwarf stack pointer register.
	 */
	@SuppressWarnings("unchecked")
	private static int readMappingsElem(Element regMappingsElem, Language lang,
			Map<Integer, Register> dwarfRegisterMap) throws IOException {

		int stackPointerIndex = -1;

		for (Element regMappingElem : (List<Element>) regMappingsElem.getChildren(
			"register_mapping")) {

			int dwarfRegNum =
				XmlUtilities.parseBoundedIntAttr(regMappingElem, "dwarf", 0, Integer.MAX_VALUE);
			String ghidraRegName = XmlUtilities.requireStringAttr(regMappingElem, "ghidra");
			boolean stackPointer =
				XmlUtilities.parseOptionalBooleanAttr(regMappingElem, "stackpointer", false);
			int autoincCount = XmlUtilities.parseOptionalBoundedIntAttr(regMappingElem,
				"auto_count", -1, 0, Integer.MAX_VALUE);
			if (autoincCount > 0) {
				Pattern regNamePattern = Pattern.compile("([a-zA-Z]+)([0-9]+)");
				Matcher m = regNamePattern.matcher(ghidraRegName);
				if (!m.matches()) {
					throw new IOException("Unsupported register name for auto-increment: " +
						ghidraRegName + ", " + XmlUtilities.toString(regMappingElem));
				}
				String baseGhidraRegName = m.group(1);
				int baseGhidraRegNum = Integer.parseInt(m.group(2));
				for (int autoIncNum = 0; autoIncNum < autoincCount; autoIncNum++) {
					String autoIncRegName =
						baseGhidraRegName + Integer.toString(baseGhidraRegNum + autoIncNum);
					Register autoIncReg = lang.getRegister(autoIncRegName);
					if (autoIncReg == null) {
						throw new IOException("Unknown Ghidra auto-increment register: " +
							autoIncRegName + ", " + XmlUtilities.toString(regMappingElem) +
							" for " + lang.getLanguageID());
					}
					int actualDwarfRegNum = dwarfRegNum + autoIncNum;
					if (dwarfRegisterMap.containsKey(actualDwarfRegNum)) {
						throw new IOException("Duplicate mapping for DWARF register " +
							actualDwarfRegNum + ": " + XmlUtilities.toString(regMappingElem));
					}
					dwarfRegisterMap.put(actualDwarfRegNum, autoIncReg);
				}
			}
			else {
				Register reg = lang.getRegister(ghidraRegName);
				if (reg == null) {
					throw new IOException("Unknown Ghidra register: " + ghidraRegName + ", " +
						XmlUtilities.toString(regMappingElem));
				}
				if (dwarfRegisterMap.containsKey(dwarfRegNum)) {
					throw new IOException("Duplicate mapping for DWARF register " + dwarfRegNum +
						": " + XmlUtilities.toString(regMappingElem));
				}

				dwarfRegisterMap.put(dwarfRegNum, reg);
				if (stackPointer) {
					stackPointerIndex = dwarfRegNum;
				}
			}
		}

		if (stackPointerIndex < 0) {
			throw new IOException("Missing stackpointer specification in registermappings");
		}

		return stackPointerIndex;
	}

}
