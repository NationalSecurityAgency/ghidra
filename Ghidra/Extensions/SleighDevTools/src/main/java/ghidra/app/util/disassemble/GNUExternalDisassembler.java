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
package ghidra.app.util.disassemble;

import java.io.*;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.jdom.*;
import org.jdom.input.SAXBuilder;

import generic.jar.ResourceFile;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.framework.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;
import util.CollectionUtils;

public class GNUExternalDisassembler implements ExternalDisassembler {

	private static final String UNSUPPORTED = "UNSUPPORTED";

	// magic values for gdis that direct it to read bytes from stdin
	private static final String READ_FROM_STDIN_PARAMETER = "stdin";
	private static final String SEPARATOR_CHARACTER = "\n";
	private static final String OPTIONS_SEPARATOR = "*";
	private static final String ADDRESS_OUT_OF_BOUNDS = "is out of bounds.";
	private static final String ENDING_STRING = "EOF";
	private static final int NUM_BYTES = 32;

	private static final String MAP_FILENAME = "LanguageMap.txt";
	private static final String GNU_DISASSEMBLER_MODULE_NAME = "GnuDisassembler";
	private static final String GDIS_EXE =
		Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS ? "gdis.exe"
				: "gdis";
	private static final String EMPTY_DISASSEMBLER_OPTIONS = "";
	private static final String GDIS_OPTIONS_FILENAME_PROPERTY = "gdis.disassembler.options.file";

	private static HashMap<String, File> languageGdisMap;
	private static File defaultGdisExecFile;
	private static File gdisDataDirectory;

	private static Map<LanguageID, GdisConfig> configCache = new HashMap<>();
	private static boolean missingExtensionReported;

	private GdisConfig currentConfig;
	private boolean hadFailure;

	private Process disassemblerProcess;
	private BufferedReader buffReader;
	private OutputStreamWriter outputWriter;

//	private LanguageID lastLanguageWarnedAbout;

	public GNUExternalDisassembler() throws Exception {
		initialize();
	}

	@Override
	public void destroy() {
		if (disassemblerProcess != null) {
			disassemblerProcess.destroy();
		}
	}

	@Override
	public boolean isSupportedLanguage(Language language) {
		GdisConfig gdisConfig = checkLanguage(language);
		return gdisConfig != null && gdisConfig.architecture != UNSUPPORTED;
	}

	@Override
	public String getDisassemblyDisplayPrefix(CodeUnit cu) throws Exception {
		GdisConfig gdisConfig = checkLanguage(cu.getProgram().getLanguage());
		if (gdisConfig == null || gdisConfig.architecture == UNSUPPORTED) {
			return null;
		}
		Register contextRegister = gdisConfig.getContextRegister();
		if (contextRegister == null) {
			return null;
		}
		long value = getContextRegisterValue(cu, contextRegister);
		String option = gdisConfig.getDisplayPrefixMap().get(value);
		return option;
	}

	private static void reportMultipleMappings(Language language) {
		List<String> externalNames = language.getLanguageDescription().getExternalNames("gnu");
		if (externalNames != null && externalNames.size() > 1) {
			LanguageID currentLanguageID = language.getLanguageID();
			StringBuilder sb = new StringBuilder();
			boolean prependSeparator = false;
			for (String name : externalNames) {
				if (prependSeparator) {
					sb.append(", ");
				}
				sb.append(name);
				prependSeparator = true;
			}
			Msg.warn(GNUExternalDisassembler.class,
				"Language " + currentLanguageID + " illegally maps to multiple (" +
					externalNames.size() + ") external gnu names: " + sb.toString() +
					".  The first external name will be used.");
		}
	}

	private static class GdisConfig {

		String languageId;
		boolean isBigEndian;

		String architecture;
		String machineId;
		File gdisExecFile;
		boolean usingDefault;
		Register contextRegister;
		Map<Long, String> valueToOptionString;
		Map<Long, String> valueToDisplayPrefix;
		Language lang;
		String globalDisassemblerOptions;

		GdisConfig(Language language, boolean isBigEndian) {

			this.languageId = language.getLanguageID().toString();
			this.isBigEndian = isBigEndian;
			this.lang = language;

			List<String> architectures = language.getLanguageDescription().getExternalNames("gnu");
			//get first non-null
			if (architectures != null && architectures.size() > 0) {
				architecture = architectures.get(0);
				if (architectures.size() > 1) {
					reportMultipleMappings(language);
				}
			}
			if (architecture == null) {
				architecture = UNSUPPORTED;
				return;
			}

			machineId = "0x0";

			// handle numeric entry which combines architecture and machineId
			if (architecture.startsWith("0x")) {
				String[] parts = architecture.split(":");
				architecture = parts[0];
				machineId = parts[1];
			}

			gdisExecFile = languageGdisMap.get(languageId);
			if (gdisExecFile == null) {
				gdisExecFile = defaultGdisExecFile;
				usingDefault = true;
			}

			List<String> gDisOptionsFile =
				language.getLanguageDescription().getExternalNames(GDIS_OPTIONS_FILENAME_PROPERTY);
			if (!CollectionUtils.isBlank(gDisOptionsFile)) {
				try {
					parseGdisOptionsFile(gDisOptionsFile.get(0));
				}
				catch (IOException e) {
					Msg.error(this, "Error reading gdis options file " + e.getMessage());
					contextRegister = null;
					valueToOptionString = null;
					valueToDisplayPrefix = null;
				}
			}
		}

		GdisConfig(Language lang) {
			this(lang, lang.isBigEndian());
		}

		private void parseGdisOptionsFile(String fileName) throws IOException {
			LanguageDescription desc = lang.getLanguageDescription();
			if (!(desc instanceof SleighLanguageDescription)) {
				throw new IOException("Not a Sleigh Language: " + lang.getLanguageID());
			}

			SleighLanguageDescription sld = (SleighLanguageDescription) desc;
			ResourceFile defsFile = sld.getDefsFile();
			ResourceFile parentFile = defsFile.getParentFile();
			ResourceFile gdisOpts = new ResourceFile(parentFile, fileName);
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			try (InputStream fis = gdisOpts.getInputStream()) {
				Document doc = sax.build(fis);
				Element rootElem = doc.getRootElement();
				Element globalElement = rootElem.getChild("global");
				if (globalElement != null) {
					globalDisassemblerOptions = globalElement.getAttributeValue("optstring");
				}
				Element contextRegisterElement = rootElem.getChild("context_register");
				if (contextRegisterElement == null) {
					//no context_register element found in the xml file 
					//this is not necessarily an error - might only be a global optstring
					//global optstring has already been parsed, so we're done
					if (globalElement != null) {
						Msg.info(this,
							"no context register element in " + gdisOpts.getAbsolutePath());
						return;
					}
					//no context register element or global element, error
					throw new JDOMException(
						"No context_register element or global element in gdis options file");
				}
				if (contextRegisterElement.getContentSize() == 0) {
					throw new JDOMException("No context register name provided.");
				}
				String contextRegisterName = contextRegisterElement.getContent(0).getValue();
				contextRegister = lang.getRegister(contextRegisterName);
				if (contextRegister == null) {
					//the context register named in the xml file does not exist in the sleigh language
					//this is an error
					throw new JDOMException("Unknown context register " + contextRegisterName +
						" for language " + lang.getLanguageID().getIdAsString());
				}
				valueToOptionString = new HashMap<>();
				valueToDisplayPrefix = new HashMap<>();
				Element options = rootElem.getChild("options");
				List<Element> optList = options.getChildren("option");
				for (Element opt : optList) {
					Long value = Long.decode(opt.getAttributeValue("value"));
					String optString = opt.getAttributeValue("optstring");
					valueToOptionString.put(value, optString);
					String displayPrefix = opt.getAttributeValue("display_prefix");
					valueToDisplayPrefix.put(value, displayPrefix);
				}

			}
			catch (JDOMException e) {
				Msg.error(this, "Error reading " + fileName + ": " + e.getMessage());
				contextRegister = null;
				valueToOptionString = null;
				valueToDisplayPrefix = null;
			}
		}

		/**
		 * Returns the global disassembler options
		 * @return global option string, or {@code null} if the
		 * global is unspecified.
		 */
		public String getGlobalDisassemblerOptions() {
			return globalDisassemblerOptions;
		}

		/**
		 * Return the context register determine by the gdis options file
		 * @return the context register
		 */
		public Register getContextRegister() {
			return contextRegister;
		}

		/**
		 * Returns the map from context register values to gdis disassembler options
		 * @return map values->options
		 */
		public Map<Long, String> getOptionsMap() {
			return valueToOptionString;
		}

		/**
		 * Returns the map from context register values to disassembly display prefixes
		 * @return map values->prefixes
		 */
		public Map<Long, String> getDisplayPrefixMap() {
			return valueToDisplayPrefix;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof GdisConfig)) {
				return false;
			}
			// assume config will match for a given language
			return languageId.equals(((GdisConfig) obj).languageId);
		}

		@Override
		public int hashCode() {
			return languageId.hashCode();
		}
	}

	private static synchronized GdisConfig checkLanguage(Language lang) {
		LanguageID languageId = lang.getLanguageID();
		if (configCache.containsKey(languageId)) {
			return configCache.get(languageId);
		}
		GdisConfig config = new GdisConfig(lang);
		if (config.architecture == UNSUPPORTED) {
			Msg.warn(GNUExternalDisassembler.class,
				"Language not supported (ldefs 'gnu' map entry not found): " + languageId);
		}
		else if (gdisDataDirectory == null) {
			config = null;
			if (!missingExtensionReported) {
				missingExtensionReported = true;
				Msg.showError(GNUExternalDisassembler.class, null, "GNU Disassembler Not Found",
					"External Disassembler extension module not installed: " +
						GNU_DISASSEMBLER_MODULE_NAME);
			}
		}
		else if (config.gdisExecFile == null) {
			boolean usingDefault = config.usingDefault;
			config = null;
			if (usingDefault) {
				if (!missingExtensionReported) {
					missingExtensionReported = true;
					Msg.showError(GNUExternalDisassembler.class, null, "GNU Disassembler Not Found",
						"External GNU Disassembler not found (requires install and build of " +
							GNU_DISASSEMBLER_MODULE_NAME + " extension): " + GDIS_EXE);
				}
			}
			else {
				Msg.showError(GNUExternalDisassembler.class, null, "GNU Disassembler Not Found",
					"External GNU Disassembler not found for language (" + lang.getLanguageID() +
						", see LanguageMap.txt)");
			}
		}
		configCache.put(languageId, config);
		return config;
	}

	private int pow2(int pow) {
		int r = 1;
		for (int i = 1; i <= pow; i++) {
			r *= 2;
		}
		return r;
	}

	/**
	 * Get detailed instruction list for a block of instructions.
	 * 
	 * @param lang
	 *            processor language (corresponding LanguageID must be defined
	 *            within LanguageMap.txt)
	 * @param blockAddr
	 *            start of block ( must be true: (offset & -(2^blockSizeFactor)
	 *            == offset)
	 * @param blockSizeFactor
	 *            the block size factor where blockSize = 2^blockSizeFactor
	 *            (must be > 0)
	 * @param byteProvider
	 *            provider for block of bytes to be disassembled starting at
	 *            offset 0
	 * @return list of instructions or null if language not supported by GNU
	 *         Disassembler
	 * @throws Exception
	 */
	public List<GnuDisassembledInstruction> getBlockDisassembly(Language lang, Address blockAddr,
			int blockSizeFactor, ByteProvider byteProvider) throws Exception {

		GdisConfig gdisConfig = checkLanguage(lang);
		if (gdisConfig == null || gdisConfig.architecture == UNSUPPORTED) {
			return null;
		}

		if (blockSizeFactor < 0 || blockSizeFactor > 8) {
			throw new IllegalArgumentException("blockSizeFactor must be > 0 and <= 8");
		}
		int blockSize = pow2(blockSizeFactor);

		if ((blockAddr.getOffset() & -blockSize) != blockAddr.getOffset()) {
			throw new IllegalArgumentException("Address must be block aligned");
		}

		long addressOffset = blockAddr.getAddressableWordOffset();
		String address = "0x" + Long.toHexString(addressOffset);

		// for aligned languages, don't try on non-aligned block addr/size.
		int alignment = lang.getInstructionAlignment();
		if (blockAddr.getOffset() % alignment != 0) {
			throw new IllegalArgumentException(
				"Address does not satisfy instruction alignment constraint: " + alignment);
		}

		String bytes = getBytes(byteProvider, blockSize);

		return runDisassembler(gdisConfig, address, bytes, EMPTY_DISASSEMBLER_OPTIONS);
	}

	public List<GnuDisassembledInstruction> getBlockDisassembly(Program program, Address addr,
			int blockSizeFactor) throws Exception {

		if (blockSizeFactor < 0 || blockSizeFactor > 8) {
			throw new IllegalArgumentException("blockSizeFactor must be > 0 and <= 8");
		}
		int blockSize = pow2(blockSizeFactor);

		Address blockAddr = addr.getNewAddress(addr.getOffset() & -blockSize); // block
		// aligned
		// address

		return getBlockDisassembly(program.getLanguage(), blockAddr, blockSizeFactor,
			new MemoryByteProvider(program.getMemory(), blockAddr));
	}

	@Override
	public String getDisassembly(CodeUnit cu) throws Exception {

		GdisConfig gdisConfig = checkLanguage(cu.getProgram().getLanguage());
		if (gdisConfig == null || gdisConfig.architecture == UNSUPPORTED) {
			return null;
		}

		long addressOffset = cu.getAddress().getAddressableWordOffset();
		String address = "0x" + Long.toHexString(addressOffset);

		// for aligned languages, don't try on non-aligned locations.
		if (cu.getMinAddress().getOffset() %
			cu.getProgram().getLanguage().getInstructionAlignment() != 0) {
			return "";
		}

		String bytes = getBytes(cu, NUM_BYTES);
		if (bytes == null) {
			return "";
		}

		String disOptions = EMPTY_DISASSEMBLER_OPTIONS;
		String globalOptions = gdisConfig.getGlobalDisassemblerOptions();
		boolean hasGlobal = false;
		if (globalOptions != null) {
			hasGlobal = true;
			//set the disOptions to the global options here in case there are global
			//options but no options for context register values
			disOptions = globalOptions;
		}
		Register contextRegister = gdisConfig.getContextRegister();
		if (contextRegister != null) {
			long value = getContextRegisterValue(cu, contextRegister);
			String contextRegisterValueOption = gdisConfig.getOptionsMap().get(value);
			if (contextRegisterValueOption == null) {
				Msg.warn(this, "No option for value " + value + " of context register " +
					contextRegister.getName());
			}
			else {
				//need to put a comma between the global options and the options
				//for this context register value
				if (hasGlobal) {
					disOptions = globalOptions + "," + contextRegisterValueOption;
				}
				//no global options, just send the options for this context register
				else {
					disOptions = contextRegisterValueOption;
				}
			}
		}
		List<GnuDisassembledInstruction> disassembly =
			runDisassembler(gdisConfig, address, bytes, disOptions);

		if (disassembly == null || disassembly.size() == 0 || disassembly.get(0) == null) {
			return "(bad)";
		}
		return disassembly.get(0).toString();
	}

	// disassembler without having to have a code unit
	@Override
	public String getDisassemblyOfBytes(Language language, boolean isBigEndian, long addressOffset,
			byte[] bytes) throws Exception {

		GdisConfig gdisConfig = new GdisConfig(language, isBigEndian);
		if (gdisConfig.architecture == UNSUPPORTED || gdisConfig.gdisExecFile == null) {
			return null;
		}

		String bytesString = converBytesToString(bytes);

		String address = "0x" + Long.toHexString(addressOffset);

		List<GnuDisassembledInstruction> disassembly =
			runDisassembler(gdisConfig, address, bytesString, EMPTY_DISASSEMBLER_OPTIONS);

		if (disassembly == null || disassembly.isEmpty() || disassembly.get(0) == null) {
			return "(bad)";
		}
		return disassembly.get(0).toString();
	}

	private long getContextRegisterValue(CodeUnit cu, Register contextRegister) {
		ProgramContext context = cu.getProgram().getProgramContext();
		RegisterValue value = context.getRegisterValue(contextRegister, cu.getAddress());
		if (value != null) {
			return value.getUnsignedValue().longValue();
		}
		//we tried, return 0 to match SLEIGH default
		return 0;
	}

	private String converBytesToString(byte[] bytes) {
		String byteString = null;
		for (byte thisByte : bytes) {
			String thisByteString = Integer.toHexString(thisByte);
			if (thisByteString.length() == 1) {
				thisByteString = "0" + thisByteString; // pad single digits
			}
			if (thisByteString.length() > 2) {
				thisByteString = thisByteString.substring(thisByteString.length() - 2);
			}
			// append this byte's hex string to the larger word length string
			byteString = byteString + thisByteString;
		}

		return byteString;
	}

	private boolean setupDisassembler(GdisConfig gdisConfig) {

		if (disassemblerProcess != null) {
			disassemblerProcess.destroy();
			disassemblerProcess = null;
			outputWriter = null;
			buffReader = null;
		}

		this.currentConfig = gdisConfig;
		hadFailure = false;

		String endianString = gdisConfig.isBigEndian ? "0x00" : "0x01"; // 0x0 is big, 0x1 is little endian

		// NOTE: valid target must be specified but has no effect on results
		String cmds[] = { gdisConfig.gdisExecFile.getAbsolutePath(), "pef", gdisConfig.architecture,
			gdisConfig.machineId, endianString, "0x0",
			gdisDataDirectory.getAbsolutePath() + File.separator,
			GNUExternalDisassembler.READ_FROM_STDIN_PARAMETER };

		StringBuilder buf = new StringBuilder();
		for (String str : cmds) {
			boolean addQuotes = str.indexOf(' ') >= 0;
			if (addQuotes) {
				buf.append('\"');
			}
			buf.append(str);
			if (addQuotes) {
				buf.append('\"');
			}
			buf.append(' ');
		}
		Msg.debug(this, "Starting gdis: " + buf.toString());

		try {
			Runtime rt = Runtime.getRuntime();
			disassemblerProcess = rt.exec(cmds, null, gdisConfig.gdisExecFile.getParentFile());
		}
		catch (IOException e) {
			buf = new StringBuilder();
			for (String arg : cmds) {
				buf.append("\"");
				buf.append(arg);
				buf.append("\" ");
			}
			Msg.debug(this, "GNU Disassembly setup failed, exec command: " + buf);
			Msg.showError(this, null, "GNU Disassembler Error",
				"Disassembler setup execution error: " + e.getMessage(), e);
			hadFailure = true;
			return false;
		}
		return true;
	}

	private List<GnuDisassembledInstruction> runDisassembler(GdisConfig gdisConfig,
			String addrString, String bytes, String disassemblerOptions) throws IOException {

		// if this is the first time running the disassembler process, or a
		// parameter has changed (notably, not the address--we pass that in
		// every time)
		boolean sameConfig = gdisConfig.equals(currentConfig);
		if (sameConfig && hadFailure) {
			return null;
		}

		if (disassemblerProcess == null || !sameConfig) {

			if (!setupDisassembler(gdisConfig)) {
				return null;
			}

			outputWriter = new OutputStreamWriter(disassemblerProcess.getOutputStream());

			InputStreamReader inStreamReader =
				new InputStreamReader(disassemblerProcess.getInputStream());
			buffReader = new BufferedReader(inStreamReader);

			ExternalStreamHandler errorHandler =
				new ExternalStreamHandler(disassemblerProcess.getErrorStream());
			errorHandler.start();
		}

		if (!disassemblerProcess.isAlive()) {
			return null; // if process previously died return nothing - quickly
		}

		String disassemblyRequest = addrString + SEPARATOR_CHARACTER + bytes;
		if (StringUtils.isEmpty(disassemblerOptions)) {
			disassemblyRequest += '\n';
		}
		else {
			disassemblyRequest += OPTIONS_SEPARATOR + disassemblerOptions + SEPARATOR_CHARACTER;
		}

		try {
			outputWriter.write(disassemblyRequest);
			outputWriter.flush();
			return getDisassembledInstruction();
		}
		catch (IOException e) {
			// force a restart of the disassembler on next call to this function
			// TODO: Should we not do this to avoid repeated failure and severe slowdown?
			// User must exit or switch configs/programs to retry after failure
			//disassemblerProcess.destroy();
			//disassemblerProcess = null; // assumes process exit
			Msg.error(this, "Last gdis request failed: " + disassemblyRequest);
			throw new IOException("gdis execution error", e);
		}
	}

	private List<GnuDisassembledInstruction> getDisassembledInstruction() throws IOException {

		List<GnuDisassembledInstruction> results = new ArrayList<>();
		String instructionLine;

		boolean error = false;
		do {
			instructionLine = buffReader.readLine();
			if (!error && instructionLine != null && !instructionLine.equals(ENDING_STRING) &&
				(instructionLine.indexOf(ADDRESS_OUT_OF_BOUNDS) < 0) &&
				!instructionLine.startsWith("Usage:") && !instructionLine.startsWith("Debug:")) {

				String instructionMetadataLine = buffReader.readLine();
				if (!instructionMetadataLine.startsWith("Info: ")) {
					// TODO, throw an "ExternalDisassemblerInterfaceException"
					// or some such
					error = true; // still need to consume remainder of input
					continue;
				}
				String[] metadata = instructionMetadataLine.substring("Info: ".length()).split(",");
				results.add(new GnuDisassembledInstruction(instructionLine.replace('\t', ' '),
					Integer.parseInt(metadata[0]), "1".equals(metadata[1]),
					Integer.parseInt(metadata[2]), Integer.parseInt(metadata[3]),
					Integer.parseInt(metadata[4])));
			}
		}
		while (instructionLine != null && !instructionLine.equals(ENDING_STRING));

		if (!disassemblerProcess.isAlive()) {
			throw new IOException("GNU disassembler process died unexpectedly.");
		}

		if (error) {
			return null;
		}

		return results;
	}

	private String getBytes(ByteProvider byteProvider, int size) throws IOException {
		StringBuffer byteString = new StringBuffer();
		for (int i = 0; i < size; i++) {
			byteString.append(formatHexString(byteProvider.readByte(i)));
		}
		return byteString.toString();
	}

	private String getBytes(MemBuffer mem, int size) {
		StringBuffer byteString = new StringBuffer();
		for (int i = 0; i < size; i++) {
			try {
				byteString.append(formatHexString(mem.getByte(i)));
			}
			catch (AddressOutOfBoundsException e) {
				break;
			}
			catch (MemoryAccessException e) {
				if (i > 0) {
					break;
				}
				return null;
			}
		}
		return byteString.toString();
	}

	private String formatHexString(byte byteToFix) {
		String byteString = "";
		String singleByte = "";
		if (byteToFix < 0) {
			singleByte = Integer.toHexString(byteToFix + 256);
		}
		else {
			singleByte = Integer.toHexString(byteToFix);
		}
		if (singleByte.length() == 1) {
			byteString += '0';
		}
		byteString += singleByte;
		return byteString;
	}

	private static synchronized void initialize() throws Exception {
		if (languageGdisMap != null) {
			return;
		}

		languageGdisMap = new HashMap<>();

		try {
			// sample elf files located in data directory
			ResourceFile dataDir =
				Application.getModuleSubDirectory(GNU_DISASSEMBLER_MODULE_NAME, "data");
			gdisDataDirectory = dataDir.getFile(false);
			defaultGdisExecFile = Application.getOSFile(GNU_DISASSEMBLER_MODULE_NAME, GDIS_EXE);
		}
		catch (FileNotFoundException e) {
			// ignore
		}

		if (gdisDataDirectory == null) {
			Msg.warn(GNUExternalDisassembler.class,
				"Use of External GNU Disassembler requires installation of extension: " +
					GNU_DISASSEMBLER_MODULE_NAME);
		}

		initializeMaps();

		if (defaultGdisExecFile == null || !defaultGdisExecFile.canExecute()) {
			Msg.warn(GNUExternalDisassembler.class,
				"External GNU Disassembler not found: " + GDIS_EXE);
			defaultGdisExecFile = null;
		}
	}

	/**
	 * Process all language maps defined by any module.  Any alternate external disassembler
	 * executable will be looked for within the os directory of the contributing module or 
	 * within the gdis module
	 * @throws Exception
	 */
	private static void initializeMaps() {
		for (ResourceFile file : Application.findFilesByExtensionInApplication(".txt")) {
			if (MAP_FILENAME.equals(file.getName())) {
				initializeMap(file);
			}
		}
	}

	private static void initializeMap(ResourceFile mapFile) {

		ResourceFile moduleForResourceFile = Application.getModuleContainingResourceFile(mapFile);
		if (moduleForResourceFile == null) {
			Msg.error(GNUExternalDisassembler.class,
				"Failed to identify module containing file: " + mapFile);
			return;
		}

		Reader mapFileReader = null;
		try {
			mapFileReader = new InputStreamReader(mapFile.getInputStream());
			BufferedReader reader = new BufferedReader(mapFileReader);
			String line = null;
			while ((line = reader.readLine()) != null) {
				if (line.startsWith("//") || line.isEmpty()) {
					continue;
				}
				String[] parts = line.split("#");
				if (parts.length > 1) {

					//System.out.println("found: " + parts[0] + " . " + parts[1]);

					// TODO: should probably store exe module/name in map and defer search 
					// until GdisConfig is created.  This will allow us to complain about a 
					// missing exe when it is needed/used.

					String gdisExe = parts[1];
					if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
						gdisExe = gdisExe + ".exe";
					}
					try {
						File customGdisExecFile;
						try {
							customGdisExecFile =
								Application.getOSFile(moduleForResourceFile.getName(), gdisExe);
						}
						catch (FileNotFoundException e) {
							customGdisExecFile = Application.getOSFile(gdisExe);
						}
						languageGdisMap.put(parts[0], customGdisExecFile);
					}
					catch (FileNotFoundException e) {
						Msg.error(GNUExternalDisassembler.class,
							"External disassembler not found (" + parts[0] + "): " + gdisExe);
					}

				}
			}
		}
		catch (Exception e) {
			Msg.error(GNUExternalDisassembler.class,
				"Error reading from language mapping file: " + mapFile, e);
		}
		finally {
			if (mapFileReader != null) {
				try {
					mapFileReader.close();
				}
				catch (Exception e) {
					// we tried
				}
			}
		}
	}
}
