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

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.util.AddressLabelInfo;
import ghidra.util.ManualEntry;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

class OldLanguage implements Language {

	private LanguageDescription langDescription;
	private Endian endian;
	private AddressFactory addressFactory;
	private RegisterManager registerMgr;
	private List<CompilerSpecDescription> associatedCompilerSpecs =
		new ArrayList<CompilerSpecDescription>();

	private final ResourceFile oldLangFile;

	/**
	 * Construct an old language. The resulting instance does not initialize the
	 * address factory or register definitions until after the validate method
	 * is invoked.
	 * 
	 * @param oldLangFile
	 * @throws IOException
	 * @see {@link #validate()}
	 */
	OldLanguage(ResourceFile oldLangFile) throws IOException {
		this.oldLangFile = oldLangFile;
		readOldLanguage(true);
	}

	/**
	 * Construct an old language from XML. Intended for test use only.
	 * 
	 * @param oldLanguageElement
	 * @throws JDOMException
	 * @throws SAXException
	 */
	OldLanguage(Element oldLanguageElement) throws JDOMException, SAXException {
		this.oldLangFile = null;
		parseOldLanguage(oldLanguageElement, false);
	}

	@Override
	public String toString() {
		return getDescription() + "(Version " + getVersion() + ")";
	}

	/**
	 * If instantiated from a file, this method must be invoked prior to the
	 * factory handing out this instance. This will complete the parsing of the
	 * old language file and the initialization of this instance.
	 * 
	 * @throws JDOMException
	 * @throws SAXException
	 * @throws IOException
	 */
	void validate() throws JDOMException, SAXException, IOException {
		if (oldLangFile != null && addressFactory == null || registerMgr == null) {
			readOldLanguage(false);
		}
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	@Override
	public ParallelInstructionLanguageHelper getParallelInstructionHelper() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getParallelInstructionHelper)");
	}

	@Override
	public int getInstructionAlignment() {
// TODO: ???
		return 1; // should not be needed for upgrade
	}

	@Override
	public LanguageID getLanguageID() {
		return langDescription.getLanguageID();
	}

	@Override
	public Register getContextBaseRegister() {
		return registerMgr.getContextBaseRegister();
	}

	@Override
	public List<Register> getContextRegisters() {
		return registerMgr.getContextRegisters();
	}

	@Override
	public Register getRegister(Address addr, int size) {
		return registerMgr.getRegister(addr, size);
	}

	@Override
	public Register getRegister(AddressSpace addrspc, long offset, int size) {
		return registerMgr.getRegister(addrspc.getAddress(offset), size);
	}

	@Override
	public Register getRegister(String name) {
		return registerMgr.getRegister(name);
	}

	@Override
	public List<Register> getRegisters() {
		return registerMgr.getRegisters();
	}

	@Override
	public List<String> getRegisterNames() {
		return registerMgr.getRegisterNames();
	}

	@Override
	public Register[] getRegisters(Address address) {
		return registerMgr.getRegisters(address);
	}

	@Override
	public int getVersion() {
		return langDescription.getVersion();
	}

	@Override
	public int getMinorVersion() {
		return -1;
	}

	@Override
	public boolean isBigEndian() {
		return endian.isBigEndian();
	}

	@Override
	public InstructionPrototype parse(MemBuffer buf, ProcessorContext context,
			boolean inDelaySlot) {
		return new InvalidPrototype(this);
	}

	@Override
	public boolean supportsPcode() {
		return false; // should not be needed for upgrade
	}

	/**
	 * Returns language description associated with this old language.
	 */
	LanguageDescription getDescription() {
		return langDescription;
	}

	//
	// Old Language File Parsing Code
	//

	private void readOldLanguage(boolean descriptionOnly) throws IOException {

		InputStream is = null;
		try {
			is = new BufferedInputStream(oldLangFile.getInputStream());
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Document document = sax.build(is);
			Element root = document.getRootElement();

			parseOldLanguage(root, descriptionOnly);

		}
		catch (SAXNotRecognizedException e) {
			throw new IOException("Failed to parse old language: " + oldLangFile, e);
		}
		catch (JDOMException e) {
			throw new IOException("Failed to parse old language: " + oldLangFile, e);
		}
		catch (SAXException e) {
			throw new IOException("Failed to parse old language: " + oldLangFile, e);
		}
		finally {
			if (is != null) {
				try {
					is.close();
				}
				catch (IOException e1) {
				}
			}
		}
	}

	void parseOldLanguage(Element root, boolean descriptionOnly)
			throws SAXNotRecognizedException, SAXException {
		if (!"language".equals(root.getName())) {
			throw new SAXNotRecognizedException("Expected language document");
		}
		int version = parseIntAttribute(root, "version");
		String endianString = root.getAttributeValue("endian");
		endian = Endian.toEndian(endianString);

		if (endian == null) {
			throw new SAXException("Invalid language endian value: " + endianString);
		}

		boolean descriptionFound = false;
		boolean spacesFound = false;
		boolean registersFound = false;

		Iterator<?> iter = root.getChildren().iterator();
		while (iter.hasNext()) {
			Element element = (Element) iter.next();
			String elementName = element.getName();
			if ("description".equals(elementName)) {
				if (descriptionFound) {
					throw new SAXException("only one 'description' element permitted");
				}
				descriptionFound = true;
				langDescription = parseDescription(element, version);
			}
			else if ("compiler".equals(elementName)) {
				associatedCompilerSpecs.add(parseCompilerSpecDescription(element));
			}
			else if ("spaces".equals(elementName)) {
				if (spacesFound) {
					throw new SAXException("only one 'spaces' element permitted");
				}
				spacesFound = true;
				if (!descriptionOnly) {
					addressFactory = parseAddressSpaces(element);
				}
			}
			else if ("registers".equals(elementName)) {
				if (registersFound) {
					throw new SAXException("only one 'registers' element permitted");
				}
				if (!spacesFound) {
					throw new SAXException(
						"'spaces' element must occur before 'registers' element within file");
				}
				registersFound = true;
				if (!descriptionOnly) {
					registerMgr = parseRegisters(element, addressFactory);
				}
			}
			else {
				throw new SAXException("Unsupported language element '" + elementName + "'");
			}
		}

		if (!descriptionFound) {
			throw new SAXException("Missing required 'description' element");
		}
		if (!spacesFound) {
			throw new SAXException("Missing required 'spaces' element");
		}
		if (!registersFound) {
			throw new SAXException("Missing required 'registers' element");
		}
	}

	private CompilerSpecDescription parseCompilerSpecDescription(Element element)
			throws SAXException {
		String name = element.getAttributeValue("name");
		String id = element.getAttributeValue("id");
		if (name == null || id == null) {
			throw new SAXException("Missing required compiler attribute (name or id)");
		}
		return new BasicCompilerSpecDescription(new CompilerSpecID(id), name);
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

	private boolean parseBooleanAttribute(Element element, String name, Boolean defaultVal)
			throws SAXException {
		String valStr = element.getAttributeValue(name);
		if (valStr == null) {
			if (defaultVal != null) {
				return defaultVal.booleanValue();
			}
			throw new SAXException(
				"Missing required " + element.getName() + " '" + name + "' attribute");
		}
		boolean val = valStr.equalsIgnoreCase("yes") | valStr.equalsIgnoreCase("true");
		if (!val && !valStr.equalsIgnoreCase("no") & !valStr.equalsIgnoreCase("false")) {
			throw new SAXException(
				"invalid boolean attribute value " + name + "=\"" + valStr + "\"");
		}
		return val;
	}

	private Address parseRegisterAddress(Element element, AddressFactory addrFactory)
			throws SAXException {
		String addrStr = element.getAttributeValue("address");
		String offsetStr = element.getAttributeValue("offset");
		if (addrStr == null && offsetStr == null) {
			throw new SAXException(
				"Missing required " + element.getName() + " 'address' or 'offset' attribute");
		}
		Address addr = null;
		if (addrStr != null) {
			if (offsetStr != null) {
				throw new SAXException(
					element.getName() + " must not specify both 'address' and 'offset' attribute");
			}
			addr = XmlProgramUtilities.parseAddress(addrFactory, addrStr);
			if (addr == null) {
				throw new SAXException(
					"invalid address attribute value: address=" + addrStr + "\"");
			}
		}
		else {
			try {
				addr = addrFactory.getRegisterSpace().getAddress(XmlUtilities.parseLong(offsetStr));
			}
			catch (Exception e) {
			}
			if (addr == null) {
				throw new SAXException("invalid register offset value: offset=" + addrStr + "\"");
			}
		}
		return addr;
	}

	private RegisterManager parseRegisters(Element element, AddressFactory addrFactory)
			throws SAXException {
		RegisterBuilder regBuilder = new RegisterBuilder();
		List<?> children = element.getChildren();
		Iterator<?> iter = children.iterator();
		while (iter.hasNext()) {
			Element childElement = (Element) iter.next();
			String elementName = childElement.getName();
			if ("context_register".equals(elementName) || "register".equals(elementName)) {
				boolean bigEndian =
					"context_register".equals(elementName) ? true : endian.isBigEndian();
				String name = childElement.getAttributeValue("name");
				if (name == null) {
					throw new SAXException("Missing required register 'name' attribute");
				}
				Address addr = parseRegisterAddress(childElement, addrFactory);
				int bitsize = parseIntAttribute(childElement, "bitsize");
				AddressSpace space = addr.getAddressSpace();

				regBuilder.addRegister(name, name, addr, (bitsize + 7) / 8, 0, bitsize, bigEndian,
					0);

				if (space.isLoadedMemorySpace() && space instanceof GenericAddressSpace) {
					((GenericAddressSpace) space).setHasMappedRegisters(true);
				}

				if ("context_register".equals(elementName)) {
					parseContextFields(childElement, regBuilder, addr, bitsize);
				}
			}
			else {
				throw new SAXException("Unsupported registers element '" + elementName + "'");
			}
		}
		return regBuilder.getRegisterManager();
	}

	private void parseContextFields(Element element, RegisterBuilder regBuilder, Address addr,
			int contextBitLength) throws SAXException {

		List<?> children = element.getChildren();
		Iterator<?> iter = children.iterator();
		while (iter.hasNext()) {
			Element childElement = (Element) iter.next();
			String elementName = childElement.getName();
			if (!"field".equals(childElement.getName())) {
				throw new SAXException(
					"Unsupported context_register element '" + elementName + "'");
			}
			String name = childElement.getAttributeValue("name");
			if (name == null) {
				throw new SAXException("Missing required field 'name' attribute");
			}
			String range = childElement.getAttributeValue("range");
			if (range == null) {
				throw new SAXException("Missing required field 'range' attribute");
			}
			int lsb = -1;
			int msb = -1;
			try {
				String[] splitRange = range.split(",");
				lsb = Integer.parseInt(splitRange[0]);
				msb = Integer.parseInt(splitRange[1]);
				int fieldBitLength = msb - lsb + 1;

				// Transpose bit numbering from Sleigh convention in file to big-endian register context bit numbering
				lsb = contextBitLength - msb - 1;
				msb = lsb + fieldBitLength - 1;
			}
			catch (Exception e) {
			}
//			if (lsb < 0 || msb < 0 || msb < lsb || lsb > 31 || msb > 31) {
//				throw new SAXException("invalid field range: " + range);
//			}
			regBuilder.addRegister(name, name, addr, (contextBitLength + 7) / 8, lsb, msb - lsb + 1,
				true, Register.TYPE_CONTEXT);
		}

	}

	private AddressFactory parseAddressSpaces(Element element) throws SAXException {
		AddressSpace defaultSpace = null;
		List<AddressSpace> list = new ArrayList<AddressSpace>();
		List<?> children = element.getChildren();
		Iterator<?> iter = children.iterator();
		int unique = 0; // used by old address map
		while (iter.hasNext()) {
			Element childElement = (Element) iter.next();
			String elementName = childElement.getName();

			if (!"space".equals(elementName) && !"segmented_space".equals(elementName)) {
				throw new SAXException("Unsupported spaces element '" + elementName + "'");
			}
			AddressSpace space;
			String name = childElement.getAttributeValue("name");
			if (name == null) {
				throw new SAXException("Missing required space 'name' attribute");
			}
			String valStr = childElement.getAttributeValue("unique");
			if (valStr != null) {
				try {
					unique = XmlUtilities.parseInt(valStr);
				}
				catch (NumberFormatException e) {
					throw new SAXException("bad attribute value unique=\"" + valStr + "\"");
				}
			}

			if ("segmented_space".equals(elementName)) {
				space = new SegmentedAddressSpace(name, unique);
			}
			else {
				String typeStr = childElement.getAttributeValue("type");
				if (typeStr == null) {
					throw new SAXException("Missing required space 'type' attribute");
				}
				int type;
				if ("ram".equalsIgnoreCase(typeStr)) {
					type = AddressSpace.TYPE_RAM;
				}
				else if ("code".equalsIgnoreCase(typeStr)) {
					type = AddressSpace.TYPE_CODE;
				}
				else if ("register".equalsIgnoreCase(typeStr)) {
					type = AddressSpace.TYPE_REGISTER;
				}
				else {
					throw new SAXException("unsupported space type: " + typeStr);
				}
				int size = parseIntAttribute(childElement, "size");
				int wordsize = 1;
				if (childElement.getAttribute("wordsize") != null) {
					wordsize = parseIntAttribute(childElement, "wordsize");
				}
				space = new GenericAddressSpace(name, 8 * size, wordsize, type, unique);
			}
			list.add(space);
			boolean isDefault = parseBooleanAttribute(childElement, "default", Boolean.FALSE);
			if (isDefault) {
				if (defaultSpace != null) {
					throw new SAXException("only one default space may be specified");
				}
				defaultSpace = space;
			}
			++unique;
		}
		if (defaultSpace == null) {
			throw new SAXException("default address space not specified");
		}
		AddressSpace[] spaces = new AddressSpace[list.size()];
		list.toArray(spaces);
		return new DefaultAddressFactory(spaces, defaultSpace);
	}

	private LanguageDescription parseDescription(Element element, int version) throws SAXException {
		LanguageID id = null;
		Processor processor = null;
		int size = 0;
		String variant = null;

		CompilerSpecID compilerSpecID = null;

		List<?> children = element.getChildren();
		Iterator<?> iter = children.iterator();
		while (iter.hasNext()) {
			Element childElement = (Element) iter.next();
			String elementName = childElement.getName();
			String text = childElement.getText().trim();
			if (elementName.equals("name")) {
				LanguageCompilerSpecPair pair =
					OldLanguageMappingService.lookupMagicString(text, false);
				if (pair != null) {
					id = pair.languageID;
					compilerSpecID = pair.compilerSpecID;
				}
				else {
					throw new SAXException("Failed to map old language name: " + text);
				}
			}
			else if (elementName.equals("id")) {
				id = new LanguageID(text);
			}
			else if (elementName.equals("processor")) {
				processor = Processor.findOrPossiblyCreateProcessor(text);
			}
			else if (elementName.equals("variant")) {
				variant = text;
			}
			else if (elementName.equals("size")) {
				try {
					size = Integer.parseInt(text);
				}
				catch (NumberFormatException e) {
					throw new SAXException(e);
				}
			}
		}
		if (id == null) {
			throw new SAXException("Missing required description 'id' or 'name' element");
		}

		// An empty compiler spec list indicates that the "id" element was specified
		List<CompilerSpecDescription> complierSpecList = new ArrayList<CompilerSpecDescription>();
		if (compilerSpecID != null) {
			complierSpecList.add(
				new BasicCompilerSpecDescription(compilerSpecID, compilerSpecID.getIdAsString()));
		}

		return new BasicLanguageDescription(id, processor, endian, endian, size, variant, "",
			version, 0, true, complierSpecList, null);
	}

	/**
	 * If this old language corresponds to a legacy language which was tied to a
	 * specific compiler specification, a suitable ID will be returned.
	 * 
	 * @return associated compiler specification ID or null if unknown
	 */
	public CompilerSpecID getOldCompilerSpecID() {
		Collection<CompilerSpecDescription> compatibleCompilerSpecDescriptions =
			langDescription.getCompatibleCompilerSpecDescriptions();
		if (!compatibleCompilerSpecDescriptions.isEmpty()) {
			return compatibleCompilerSpecDescriptions.iterator().next().getCompilerSpecID();
		}
		return null;
	}

	@Override
	public Register getProgramCounter() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getProgramCounter)");
	}

	@Override
	public int getNumberOfUserDefinedOpNames() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getNumberOfUserDefinedOpNames)");
	}

	@Override
	public String getUserDefinedOpName(int index) {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getUserDefinedOpName)");
	}

	@Override
	public boolean isVolatile(Address addr) {
		throw new UnsupportedOperationException("Language for upgrade use only (isVolatile)");
	}

	@Override
	public void applyContextSettings(DefaultProgramContext ctx) {
	}

	@Override
	public List<CompilerSpecDescription> getCompatibleCompilerSpecDescriptions() {
		return new ArrayList<CompilerSpecDescription>(associatedCompilerSpecs);
	}

	@Override
	public CompilerSpec getDefaultCompilerSpec() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getDefaultCompilerSpec)");
	}

	@Override
	public CompilerSpec getCompilerSpecByID(CompilerSpecID compilerSpecID)
			throws CompilerSpecNotFoundException {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getCompilerSpecByID)");
	}

	@Override
	public MemoryBlockDefinition[] getDefaultMemoryBlocks() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getDefaultMemoryBlocks)");
	}

	@Override
	public List<AddressLabelInfo> getDefaultSymbols() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getDefaultSymbols)");
	}

	@Override
	public LanguageDescription getLanguageDescription() {
		return langDescription;
	}

	@Override
	public Processor getProcessor() {
		return langDescription.getProcessor();
	}

	@Override
	public String getSegmentedSpace() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getSegmentedSpace)");
	}

	@Override
	public AddressSetView getVolatileAddresses() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getVolatileAddresses)");
	}

	@Override
	public void reloadLanguage(TaskMonitor taskMonitor) {
		throw new UnsupportedOperationException("Language for upgrade use only (reloadLanguage)");
	}

	public int getAddressShiftAmount() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getAddressShiftAmount)");
	}

	private static Set<String> EMPTY_SET = Collections.unmodifiableSet(new HashSet<String>());

	@Override
	public String getProperty(String key) {
		return null;
	}

	@Override
	public Set<String> getPropertyKeys() {
		return EMPTY_SET;
	}

	@Override
	public String getProperty(String key, String defaultString) {
		return defaultString;
	}

	@Override
	public boolean getPropertyAsBoolean(String key, boolean defaultBoolean) {
		return defaultBoolean;
	}

	@Override
	public int getPropertyAsInt(String key, int defaultInt) {
		return defaultInt;
	}

	@Override
	public boolean hasProperty(String key) {
		return false;
	}

	@Override
	public ManualEntry getManualEntry(String instructionMnemonic) {
		return null;
	}

	@Override
	public Set<String> getManualInstructionMnemonicKeys() {
		return EMPTY_SET;
	}

	@Override
	public boolean hasManual() {
		return false;
	}

	@Override
	public AddressSpace getDefaultDataSpace() {
		return addressFactory.getDefaultAddressSpace();
	}

	@Override
	public AddressSpace getDefaultSpace() {
		return addressFactory.getDefaultAddressSpace();
	}

	@Override
	public Exception getManualException() {
		return null;
	}

	@Override
	public List<Register> getSortedVectorRegisters() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getSortedVectorRegisters)");
	}
}
