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
package ghidra.app.plugin.processors.sleigh;

import static utilities.util.FileUtilities.*;

import java.io.IOException;
import java.time.Duration;
import java.util.*;

import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;
import utilities.util.FileResolutionResult;

/**
 * Searches resources for spec files and provides LanguageDescriptions for these
 * specifications
 */
public class SleighLanguageProvider implements LanguageProvider {
	/**
	 * Returns a singleton instance of a {@link SleighLanguageProvider}.
	 * 
	 * @return singleton {@link SleighLanguageProvider}
	 */
	public static synchronized SleighLanguageProvider getSleighLanguageProvider() {
		if (instance == null) {
			instance = new SleighLanguageProvider();
		}
		return instance;
	}

	private static SleighLanguageProvider instance; // sleigh language provider instance (singleton)

	/**
	 * Property that can be set as a jvm startup option to control the sla lock timeout duration.
	 * <p>
	 * See {@link #LANGUAGE_LOCK_TIMEOUT}.
	 */
	public static final String LANGUAGE_LOCK_TIMEOUT_PROPNAME =
		"ghidra.app.plugin.processors.sleigh.SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT_MS";

	private final Map<LanguageID, LanguageRec> languages = new LinkedHashMap<>(); // preserve load order
	private int failureCount = 0;

	/**
	 * Construct sleigh language provider (singleton use)
	 */
	private SleighLanguageProvider() {
		try {
			createLanguages();
		}
		catch (Exception e) {
			Msg.error(SleighLanguageProvider.class,
				"Sleigh language provider initialization failed", e);
		}
	}

	/**
	 * Construct language provider (intended for test use only)
	 * @param ldefsFile language definitions file
	 * @throws SAXException if parse error occurs
	 * @throws IOException if IO error occurs
	 */
	SleighLanguageProvider(ResourceFile ldefsFile) throws SAXException, IOException {
		createLanguages(ldefsFile);
	}

	private void createLanguages() throws Exception {
		Iterable<ResourceFile> files = Application.findFilesByExtensionInApplication(".ldefs");
		for (ResourceFile file : files) {
			createLanguages(file);
		}
	}

	private void createLanguages(ResourceFile file) throws SAXException, IOException {
		try {
			SleighLanguageValidator.validateLdefsFile(file);
			createLanguageDescriptions(file);
		}
		catch (SleighException e) {
			++failureCount;
			if (e instanceof SleighFileException) {
				// no need for stack trace
				Msg.showError(this, null, "Problem loading " + file.getName(), e.getMessage());
			}
			else {
				Msg.showError(this, null, "Problem loading " + file.getName(),
					"Validation error: " + e.getMessage(), e);
			}
		}
	}

	@Override
	public boolean hadLoadFailure() {
		return failureCount != 0;
	}

	@Override
	public boolean isLanguageLoaded(LanguageID languageId) {
		return languages.getOrDefault(languageId, LanguageRec.NOT_FOUND).lang != null;
	}

	@Override
	public SleighLanguage getLanguage(LanguageID languageId, TaskMonitor monitor)
			throws LanguageNotFoundException {
		LanguageRec langRec = languages.getOrDefault(languageId, LanguageRec.NOT_FOUND);
		if (langRec != LanguageRec.NOT_FOUND && langRec.lang == null) {
			if (langRec.isRepeatFailedLangFile()) {
				throw new LanguageNotFoundException(languageId, langRec.th);
			}
			langRec.loadLanguage(monitor);
		}
		return langRec.lang;
	}


	/**
	 * Returns the {@link SleighLanguageDescription language description} of the specified language
	 * 
	 * @param languageId {@link LanguageID}
	 * @return {@link SleighLanguageDescription}
	 */
	public SleighLanguageDescription getLanguageDescription(LanguageID languageId) {
		return languages.getOrDefault(languageId, LanguageRec.NOT_FOUND).langDesc;
	}

	void unloadLanguage(LanguageID languageId) {
		LanguageRec langRec = languages.get(languageId);
		if (langRec != null) {
			langRec.unloadLanguage();
		}
	}

	@Override
	public LanguageDescription[] getLanguageDescriptions() {
		return languages.values()
				.stream()
				.map(langRec -> langRec.langDesc)
				.toArray(LanguageDescription[]::new);
	}

	private void createLanguageDescriptions(ResourceFile specFile)
			throws SAXException, IOException {
		XmlPullParser parser =
			XmlPullParserFactory.create(specFile, loggingErrorHandler(specFile), false);
		try {
			read(parser, specFile.getParentFile(), specFile.getName());
		}
		finally {
			parser.dispose();
		}
	}

	private void read(XmlPullParser parser, ResourceFile parentDirectory, String ldefs) {
		LanguageID id;
		Endian endian;
		Endian instructionEndian;
		int size;
		String variant;
		String processorName;
		int version;
		int minorVersion;
		String descriptionText;
		boolean deprecated;
		String slafilename;
		String pspec;
		String manualindexfile;
		ArrayList<CompilerSpecDescription> compilerSpecs;

		XmlElement start = parser.start("language_definitions");
		XmlElement languageEnter;
		while ((languageEnter = parser.softStart("language")) != null) {

			boolean hidden = SpecXmlUtils.decodeBoolean(languageEnter.getAttribute("hidden"));
			if (hidden && !SystemUtilities.isInDevelopmentMode()) {
				parser.discardSubTree(languageEnter);
				continue;
			}

			id = new LanguageID(languageEnter.getAttribute("id"));
			processorName = languageEnter.getAttribute("processor");
			endian = Endian.valueOf(languageEnter.getAttribute("endian").toUpperCase());
			instructionEndian = endian;
			if (languageEnter.hasAttribute("instructionEndian")) {
				instructionEndian =
					Endian.valueOf(languageEnter.getAttribute("instructionEndian").toUpperCase());
			}
			size = SpecXmlUtils.decodeInt(languageEnter.getAttribute("size"));
			variant = languageEnter.getAttribute("variant");
			String text = languageEnter.getAttribute("version");
			String[] versionPieces = text.split("\\.");
			version = 1;
			minorVersion = 0;
			try {
				version = SpecXmlUtils.decodeInt(versionPieces[0]);
				if (versionPieces.length > 1) {
					minorVersion = SpecXmlUtils.decodeInt(versionPieces[1]);
				}
			}
			catch (Exception e) {
				throw new SleighException(
					"Version tag must specify address <major>[.<minor>] version numbers", e);
			}
			deprecated = SpecXmlUtils.decodeBoolean(languageEnter.getAttribute("deprecated"));
			slafilename = languageEnter.getAttribute("slafile");
			manualindexfile = languageEnter.getAttribute("manualindexfile");
			pspec = languageEnter.getAttribute("processorspec");

			compilerSpecs = new ArrayList<CompilerSpecDescription>();

			while (!parser.peek().getName().equals("description")) {
				parser.discardSubTree();
			}
			XmlElement descriptionStart = parser.start();

			XmlElement descriptionEnd = parser.end(descriptionStart);
			descriptionText = descriptionEnd.getText();

			Map<String, Integer> truncatedSpaceMap = null;

			Map<String, List<String>> externalNameMap = new HashMap<String, List<String>>();

			XmlElement compiler;
			XmlElement element;
			SleighLanguageDescription description;
			XmlElement externalName;

			while ((element = parser.softStart("truncate_space")) != null) {
				String spaceName = element.getAttribute("space");
				int truncatedSize = SpecXmlUtils.decodeInt(element.getAttribute("size"));
				if (truncatedSpaceMap == null) {
					truncatedSpaceMap = new HashMap<String, Integer>();
				}
				if (truncatedSpaceMap.put(spaceName, truncatedSize) != null) {
					throw new SleighException(
						"truncated space '" + spaceName + "' alread specified");
				}
				parser.end(element);
			}
			while ((compiler = parser.softStart("compiler")) != null) {
				String compilerID = compiler.getAttribute("id");
				CompilerSpecID compilerSpecID = new CompilerSpecID(compilerID);
				String compilerSpecName = compiler.getAttribute("name");
				String compilerSpecFilename = compiler.getAttribute("spec");
				ResourceFile compilerSpecFile = SleighLanguageFile
						.getLanguageResourceFile(parentDirectory, compilerSpecFilename, ".cspec");
				SleighCompilerSpecDescription sleighCompilerSpecDescription =
					new SleighCompilerSpecDescription(compilerSpecID, compilerSpecName,
						compilerSpecFile);
				compilerSpecs.add(sleighCompilerSpecDescription);
				parser.end(compiler);
			}
			while ((externalName = parser.softStart("external_name")) != null) {
				String tool = externalName.getAttribute("tool");
				String name = externalName.getAttribute("name");

				if (tool != null && name != null && tool.length() > 0 && name.length() > 0) {
					List<String> nameList = externalNameMap.get(tool);
					if (nameList == null) {
						nameList = new ArrayList<String>();
						externalNameMap.put(tool, nameList);
					}
					nameList.add(name);
				}
				parser.end(externalName);
			}

			// skip any deprecated-specl-tags, or anything else for that matter
			while (!parser.peek().isEnd()) {
				parser.discardSubTree();
			}

			// skip the language end tag
			parser.end(languageEnter);
			description = new SleighLanguageDescription(id, descriptionText,
				Processor.findOrPossiblyCreateProcessor(processorName), endian, instructionEndian,
				size, variant, version, minorVersion, deprecated, truncatedSpaceMap, compilerSpecs,
				externalNameMap);
			final ResourceFile defsFile = new ResourceFile(parentDirectory, ldefs);
			FileResolutionResult result = existsAndIsCaseDependent(defsFile);
			if (!result.isOk()) {
				throw new SleighException("ldefs file " + defsFile +
					" is not properly case dependent: " + result.getMessage());
			}
			description.setDefsFile(defsFile);

			ResourceFile specFile =
				SleighLanguageFile.getLanguageResourceFile(parentDirectory, pspec, ".pspec");
			description.setSpecFile(specFile);

			SleighLanguageFile langFile =
				SleighLanguageFile.fromSlaFilename(parentDirectory, slafilename);
			description.setLanguageFile(langFile);

			try {
				if (manualindexfile != null) {
					ResourceFile manualIndexFile = SleighLanguageFile
							.getLanguageResourceFile(parentDirectory, manualindexfile, ".idx");
					description.setManualIndexFile(manualIndexFile);
				}
			}
			catch (SleighException ex) { // Error with the manual shouldn't prevent language from loading
				Msg.error(this, ex.getMessage());
			}
			if (languages.put(id, new LanguageRec(description)) != null) {
				Msg.showError(this, null, "Duplicate Sleigh Language ID",
					"Language " + id + " previously defined: " + defsFile);
			}
		}
		parser.end(start);
	}

	//---------------------------------------------------------------------------------------------
	/**
	 * Timeout used when trying to acquire the sla file lock.  (Default: 60 seconds)
	 * <p> 
	 * The sla lock is acquired and held during .sla file checking and writing (compiling).
	 * Currently parsing the sla xml is done after releasing the lock.
	 * <p>
	 * If a Ghidra process is trying to fetch a sleigh language, which requires acquiring the lock 
	 * on a sla file, and it times out before succeeding, the caller will get a 
	 * {@link LanguageNotFoundException} exception.
	 * <p>
	 * This timeout should be long enough to allow the process that has the lock to finish
	 * compiling and writing the slaspec so that the waiting process does not give up too quickly
	 * and give an error to the user.
	 * 
	 * See {@link #LANGUAGE_LOCK_TIMEOUT_PROPNAME}.
	 */
	public static final Duration LANGUAGE_LOCK_TIMEOUT = getLanguageLockTimeout();

	private static final int DEFAULT_LOCK_TIMEOUT_SECS = 60;

	private static Duration getLanguageLockTimeout() {
		String langLockTimeoutOverride = System.getProperty(LANGUAGE_LOCK_TIMEOUT_PROPNAME);
		if (langLockTimeoutOverride != null) {
			try {
				return Duration.ofMillis(Long.parseLong(langLockTimeoutOverride));
			}
			catch (NumberFormatException e) {
				// fallthru
			}
		}
		return Duration.ofSeconds(DEFAULT_LOCK_TIMEOUT_SECS);
	}

	private static class LanguageRec {
		static final LanguageRec NOT_FOUND = new LanguageRec(null);

		SleighLanguage lang;
		SleighLanguageDescription langDesc;
		Long badSlaspecTS;
		Throwable th;

		LanguageRec(SleighLanguageDescription langDesc) {
			this.langDesc = langDesc;
		}

		void markLangFileFailed(Throwable e) {
			ResourceFile slaSpecFile = langDesc.getLanguageFile().getSlaSpecFile();
			badSlaspecTS = slaSpecFile.lastModified();
			th = e;
		}

		boolean isRepeatFailedLangFile() {
			if (th instanceof SleighFileLockException) {
				// allow user to retry getting langauge because the exception would have had a built-in delay				
				return false;
			}
			// Prevents trying to load the same language over and over again, but still allows the
			// user/developer to fix a slaspec file (and change its timestamp) and try to load it
			// again without having to restart ghidra.  Does not consider timestamps of sinc files.
			if (badSlaspecTS != null) {
				ResourceFile slaSpecFile = langDesc.getLanguageFile().getSlaSpecFile();
				long slaSpecTS = slaSpecFile.lastModified();
				if (slaSpecTS != badSlaspecTS) {
					badSlaspecTS = null;
				}
			}
			return badSlaspecTS != null;
		}

		/**
		 * Loads the language.
		 *  
		 * @param monitor {@link TaskMonitor}.  See 
		 * {@link SleighLanguage#SleighLanguage(SleighLanguageDescription, TaskMonitor)} for notes
		 * about how the TaskMonitor's settings are modified during loading.
		 * @throws LanguageNotFoundException if error reading language info
		 */
		void loadLanguage(TaskMonitor monitor) throws LanguageNotFoundException {
			try {
				lang = new SleighLanguage(langDesc, monitor);
				badSlaspecTS = null;
			}
			catch (SleighException e) {
				markLangFileFailed(e);
				if (!(e instanceof SleighFileException)) {
					// don't force showing error if its just a missing file because it will be displayed elsewhere
					Msg.showError(this, null, "Error",
						"Failed to read language %s".formatted(langDesc.getLanguageFile()), e);
				}
				throw new LanguageNotFoundException(langDesc.getLanguageID(), e);
			}
		}

		void unloadLanguage() {
			lang = null;
			badSlaspecTS = null;
			th = null;
		}
	}

	/**
	 * Creates a SAX ErrorHandler that re-throws the exceptions, ignores the warning
	 * 
	 * @return new {@link ErrorHandler}
	 */
	static ErrorHandler throwingErrorHandler() {
		return new ErrorHandler() {
			@Override
			public void warning(SAXParseException exception) throws SAXException {
				// ignore
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw exception;
			}
		};
	}

	/**
	 * Creates a SAX ErrorHandler that logs the exceptions
	 * 
	 * @param specFile the input file 
	 * @return new {@link ErrorHandler}
	 */
	static ErrorHandler loggingErrorHandler(ResourceFile specFile) {
		return new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				Msg.error(SleighLanguageProvider.class, "Error parsing " + specFile, exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				Msg.error(SleighLanguageProvider.class, "Fatal error parsing " + specFile,
					exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(SleighLanguageProvider.class, "Warning parsing " + specFile, exception);
			}
		};
	}

}
