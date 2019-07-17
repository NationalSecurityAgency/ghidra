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
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;

import generic.jar.ResourceFile;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

/**
 * <code>SimpleLanguageTranslator</code> provides a simple translator which
 * derives its mappings from an XML translation specification file.
 */
class SimpleLanguageTranslator extends LanguageTranslatorAdapter {

	static final Logger log = LogManager.getLogger(SimpleLanguageTranslator.class);

	private boolean isValid = false;
	private final String translatorSpecSource;
	private final HashMap<String, String> spaceNameMap = new HashMap<String, String>();
	private final Map<String, String> registerNameMap = new HashMap<String, String>(); // old register name to new register name
	private final Map<String, BigInteger> contextSettings = new HashMap<String, BigInteger>();
	private final Map<String, String> compilerSpecMap = new HashMap<String, String>();
	private boolean clearAllContext;
	private Class<? extends LanguagePostUpgradeInstructionHandler> postUpgradeInstructionHandlerClass;

	private SimpleLanguageTranslator(String translatorSpecSource, LanguageID oldLanguageID,
			int oldLanguageVersion, LanguageID newLanguageID, int newLanguageVersion) {
		super(oldLanguageID, oldLanguageVersion, newLanguageID, newLanguageVersion);
		this.translatorSpecSource = translatorSpecSource;
	}

	@Override
	public boolean isValid() {

		if (isValid) {
			return true;
		}

		if (!super.isValid()) {
			return false;
		}

		if (spaceNameMap.isEmpty()) {
			try {
				validateDefaultSpaceMap();
			}
			catch (IncompatibleLanguageException e) {
				log.error("Bad translation spec (" + e.getMessage() + "): " + this);
				return false;
			}
		}
		else {

			AddressFactory oldFactory = getOldLanguage().getAddressFactory();
			AddressFactory newFactory = getNewLanguage().getAddressFactory();

			StringBuffer errBuf = new StringBuffer();
			ArrayList<AddressSpace> oldSpaces =
				new ArrayList<AddressSpace>(Arrays.asList(oldFactory.getPhysicalSpaces()));
			for (String name : spaceNameMap.keySet()) {
				AddressSpace space = oldFactory.getAddressSpace(name);
				oldSpaces.remove(space);
				if (space == null) {
					errBuf.append("  Mapped address space not found (from): " + name + "\r\n");
					continue;
				}
				String newName = spaceNameMap.get(name);
				if (newName == null) {
					if (oldFactory.getDefaultAddressSpace() == space) {
						errBuf.append("  Default space must be mapped: " + name + "\r\n");
					}
					continue;
				}
				AddressSpace newSpace = newFactory.getAddressSpace(newName);
				if (newSpace == null) {
					errBuf.append("  Mapped address space not found (to): " + name + "\r\n");
					continue;
				}
			}

			if (!oldSpaces.isEmpty()) {
				errBuf.append("  Failed to map old address spaces: ");
				for (AddressSpace space : oldSpaces) {
					errBuf.append(space.getName());
					errBuf.append(" ");
				}
				errBuf.append("\r\n");
			}
			if (errBuf.length() != 0) {
				log.error("Bad translation spec (details follow): " + this);
				log.error(errBuf.toString());
				return false;
			}
		}

		isValid = true;
		return true;
	}

	@Override
	public AddressSpace getNewAddressSpace(String oldSpaceName) {
		if (!isValid) {
			throw new IllegalStateException("Translator has not been validated");
		}
		if (spaceNameMap.isEmpty()) {
			return super.getNewAddressSpace(oldSpaceName);
		}
		String newName = spaceNameMap.get(oldSpaceName);
		if (newName != null) {
			return getNewLanguage().getAddressFactory().getAddressSpace(newName);
		}
		return null;
	}

	@Override
	public boolean isValueTranslationRequired(Register oldReg) {

		if ((clearAllContext || contextSettings != null) && oldReg.isBaseRegister() &&
			oldReg.isProcessorContext()) {
			return true;
		}
		return super.isValueTranslationRequired(oldReg);
	}

	@Override
	public RegisterValue getNewRegisterValue(RegisterValue oldRegisterValue) {
		Register oldReg = oldRegisterValue.getRegister();
		if (!oldReg.isProcessorContext()) {
			return super.getNewRegisterValue(oldRegisterValue);
		}
		Register newContextReg = getNewLanguage().getContextBaseRegister();
		if (newContextReg == null || (clearAllContext && contextSettings == null)) {
			return null;
		}
		RegisterValue newValue = null;
		if (!clearAllContext) {
			newValue = super.getNewRegisterValue(oldRegisterValue);
		}
		if (contextSettings == null) {
			return newValue;
		}
		if (newValue == null) {
			newValue = new RegisterValue(newContextReg);
		}
		for (Register subReg : newContextReg.getChildRegisters()) {
			BigInteger val = contextSettings.get(subReg.getName());
			if (val != null) {
				newValue = newValue.combineValues(new RegisterValue(subReg, val));
			}
		}
		return newValue;
	}

	@Override
	public CompilerSpecID getNewCompilerSpecID(CompilerSpecID oldCompilerSpecID) {
		String oldSpecId = oldCompilerSpecID.getIdAsString();
		String newSpecId = compilerSpecMap.get(oldSpecId);
		if (newSpecId != null) {
			return new CompilerSpecID(newSpecId);
		}
		return super.getNewCompilerSpecID(oldCompilerSpecID);
	}

	@Override
	public Register getNewRegister(Register oldReg) {
		if (registerNameMap != null) {
			String newName = registerNameMap.get(oldReg.getName());
			if (newName != null) {
				return getNewLanguage().getRegister(newName);
			}
		}
		return super.getNewRegister(oldReg);
	}

	@Override
	public void fixupInstructions(Program program, Language oldLanguage, TaskMonitor monitor)
			throws Exception, CancelledException {
		if (postUpgradeInstructionHandlerClass != null) {
			LanguagePostUpgradeInstructionHandler postUpgradeInstructionHandler =
				getPostUpgradeInstructionHandler(program, postUpgradeInstructionHandlerClass);
			postUpgradeInstructionHandler.fixupInstructions(oldLanguage, monitor);
		}
	}

	private static LanguagePostUpgradeInstructionHandler getPostUpgradeInstructionHandler(
			Program program, Class<?> handlerClass) throws Exception {
		if (!LanguagePostUpgradeInstructionHandler.class.isAssignableFrom(handlerClass)) {
			throw new Exception(handlerClass.getName() + " must extend " +
				LanguagePostUpgradeInstructionHandler.class.getName());
		}
		Constructor<?> constructor = handlerClass.getConstructor(new Class<?>[] { Program.class });
		return (LanguagePostUpgradeInstructionHandler) constructor.newInstance(
			new Object[] { program });
	}

	@Override
	public String toString() {
		return "[" + getOldLanguageID() + " (Version " + getOldVersion() + ")] -> [" +
			getNewLanguageID() + " (Version " + getNewVersion() + ")] {" + translatorSpecSource +
			"}";
	}

	/**
	 * Perform minimal parsing of translatorSpecFile and return new instance of
	 * a SimpleLanguageTranslator.
	 * 
	 * @param translatorSpecFile
	 * @return new SimpleLanguageTranslator instance which has not been
	 *         validated.
	 * @throws IOException
	 * @throws JDOMException
	 * @throws SAXException
	 * @see #isValid
	 */
	static SimpleLanguageTranslator getSimpleLanguageTranslator(ResourceFile translatorSpecFile)
			throws SAXException, JDOMException, IOException {

		InputStream is = new BufferedInputStream(translatorSpecFile.getInputStream());
		try {
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Document document = sax.build(is);
			Element root = document.getRootElement();
			return getSimpleLanguageTranslator(translatorSpecFile.getAbsolutePath(), root);

		}
		finally {
			try {
				is.close();
			}
			catch (IOException e1) {
				// ignore
			}
		}
	}

	/**
	 * Generate a simple language translator from XML source
	 * 
	 * @param translatorSpecSource
	 * @param languageTranslationElement
	 * @return simple language translator
	 * @throws SAXException
	 */
	static SimpleLanguageTranslator getSimpleLanguageTranslator(String translatorSpecSource,
			Element languageTranslationElement) throws SAXException {

		if (!"language_translation".equals(languageTranslationElement.getName())) {
			throw new SAXNotRecognizedException("Expected language_translation document");
		}

		LanguageID fromLanguageID = null;
		LanguageID toLanguageID = null;
		int fromLanguageVersion = -1;
		int toLanguageVersion = -1;

		Map<String, String> spaceMap = new HashMap<String, String>();
		Map<String, String> registerMap = new HashMap<String, String>();
		Map<String, BigInteger> contextSettings = new HashMap<String, BigInteger>();
		Map<String, String> compilerSpecMap = new HashMap<String, String>();
		boolean clearAllContext = false;
		Class<? extends LanguagePostUpgradeInstructionHandler> postUpgradeInstructionHandlerClass =
			null;

		HashSet<String> newSpacesMapped = new HashSet<String>();
		Iterator<?> iter = languageTranslationElement.getChildren().iterator();
		while (iter.hasNext()) {
			Element element = (Element) iter.next();
			String elementName = element.getName();
			if ("from_language".equals(elementName)) {
				if (fromLanguageID != null) {
					throw new SAXException("only one 'from_language' element permitted");
				}
				fromLanguageVersion = parseIntAttribute(element, "version");
				fromLanguageID = getLanguageId(element.getText());
			}
			else if ("to_language".equals(elementName)) {
				if (toLanguageID != null) {
					throw new SAXException("only one 'to_language' element permitted");
				}
				toLanguageVersion = parseIntAttribute(element, "version");
				toLanguageID = getLanguageId(element.getText());
			}
			else if ("map_space".equals(elementName)) {
				parseMapEntry(element, spaceMap, newSpacesMapped);
			}
			else if ("delete_space".equals(elementName)) {
				parseDeleteEntry(element, spaceMap);
			}
			else if ("map_register".equals(elementName)) {
				parseMapEntry(element, registerMap, null);
			}
			else if ("set_context".equals(elementName)) {
				parseSetContext(element, contextSettings);
			}
			else if ("clear_all_context".equals(elementName)) {
				clearAllContext = true;
			}
			else if ("map_compiler_spec".equals(elementName)) {
				parseMapEntry(element, compilerSpecMap, null);
			}
			else if ("post_upgrade_handler".equals(elementName)) {
				if (postUpgradeInstructionHandlerClass != null) {
					throw new SAXException("Only a single post_upgrade_analzer may be specified");
				}
				postUpgradeInstructionHandlerClass = parsePostUpgradeHandlerEntry(element);
			}
			else {
				throw new SAXException(
					"Unsupported language translator element '" + elementName + "'");
			}
		}

		if (fromLanguageID == null || fromLanguageID.getIdAsString().trim().length() == 0) {
			throw new SAXException("Missing valid 'from_language' element");
		}
		if (toLanguageID == null || toLanguageID.getIdAsString().trim().length() == 0) {
			throw new SAXException("Missing valid 'to_language' element");
		}
		if (fromLanguageID.equals(toLanguageID) && fromLanguageVersion >= toLanguageVersion) {
			throw new SAXException("Invalid language translator versions: " + fromLanguageVersion +
				" -> " + toLanguageVersion);
		}

		SimpleLanguageTranslator translator = new SimpleLanguageTranslator(translatorSpecSource,
			fromLanguageID, fromLanguageVersion, toLanguageID, toLanguageVersion);
		translator.spaceNameMap.putAll(spaceMap);
		translator.registerNameMap.putAll(registerMap);
		translator.contextSettings.putAll(contextSettings);
		translator.compilerSpecMap.putAll(compilerSpecMap);
		translator.clearAllContext = clearAllContext;
		translator.postUpgradeInstructionHandlerClass = postUpgradeInstructionHandlerClass;
		return translator;
	}

	private static LanguageID getLanguageId(String name) {
		LanguageCompilerSpecPair pair = OldLanguageMappingService.lookupMagicString(name, false);
		if (pair != null) {
			return pair.languageID;
		}
		return new LanguageID(name);
	}

	private static int parseIntAttribute(Element element, String name) throws SAXException {
		String valStr = element.getAttributeValue(name);
		if (valStr == null) {
			throw new SAXException(
				"Missing required " + element.getName() + " '" + name + "' attribute");
		}
		try {
			return XmlUtilities.parseInt(valStr);
		}
		catch (NumberFormatException e) {
			throw new SAXException(
				"invalid integer attribute value: " + name + "=\"" + valStr + "\"");
		}
	}

	@SuppressWarnings("unchecked")
	private static Class<? extends LanguagePostUpgradeInstructionHandler> parsePostUpgradeHandlerEntry(
			Element element) throws SAXException {

		String className = element.getAttributeValue("class");
		if (className == null) {
			throw new SAXException(element.getName() + " must specify 'class' attribute");
		}
		try {
			Class<?> clazz = Class.forName(className);
			getPostUpgradeInstructionHandler((Program) null, clazz); // test construction
			return (Class<? extends LanguagePostUpgradeInstructionHandler>) clazz;
		}
		catch (Exception e) {
			if (e instanceof SAXException) {
				throw (SAXException) e;
			}
			throw new SAXException("Failed to instantiate: " + className, e);
		}
	}

	private static void parseMapEntry(Element element, Map<String, String> nameMap,
			HashSet<String> toDuplicateCheckSet) throws SAXException {

		String fromName = element.getAttributeValue("from");
		String toName = element.getAttributeValue("to");
		if (fromName == null || toName == null) {
			throw new SAXException(
				element.getName() + " must include both 'from' and 'to' attributes");
		}
		if (toDuplicateCheckSet != null) {
			if (toDuplicateCheckSet.contains(toName)) {
				throw new SAXException(
					element.getName() + " may not map to the same name more than once: " + toName);
			}
			toDuplicateCheckSet.add(toName);
		}
		if (nameMap.containsKey(fromName)) {
			throw new SAXException(
				element.getName() + " may not map the same name more than once: " + fromName);
		}
		nameMap.put(fromName, toName);
	}

	private static void parseDeleteEntry(Element element, Map<String, String> nameMap)
			throws SAXException {

		String name = element.getAttributeValue("name");
		if (name == null) {
			throw new SAXException(element.getName() + " must include 'name' attribute");
		}
		if (nameMap.containsKey(name)) {
			throw new SAXException(
				element.getName() + " may not map the same name more than once: " + name);
		}
		nameMap.put(name, null);
	}

	private static void parseSetContext(Element element, Map<String, BigInteger> contextSettings)
			throws SAXException {
		String name = element.getAttributeValue("name");
		if (name == null) {
			throw new SAXException("Missing required set_context 'name' attribute");
		}
		String valStr = element.getAttributeValue("value");
		if (valStr == null) {
			throw new SAXException("Missing required set_context 'value' attribute");
		}
		BigInteger val;
		try {
			if (valStr.startsWith("0x")) {
				valStr = valStr.substring(2);
				val = new BigInteger(valStr, 16);
			}
			else {
				val = new BigInteger(valStr);
			}
		}
		catch (NumberFormatException e) {
			throw new SAXException(
				"invalid set_context attribute value: " + name + "=\"" + valStr + "\"");
		}
		contextSettings.put(name, val);
	}

	public CompilerSpec getCompilerSpec() {
		// TODO Auto-generated method stub
		return null;
	}

}
