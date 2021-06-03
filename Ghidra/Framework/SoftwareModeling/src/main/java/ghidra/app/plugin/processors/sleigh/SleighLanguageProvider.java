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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;

import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;
import utilities.util.FileResolutionResult;

/**
 * Searches resources for spec files and provides LanguageDescriptions for these
 * specifications
 */
public class SleighLanguageProvider implements LanguageProvider {

	/**
	 * <pre>
	 * Raw:     .*(\/|\\)\.\.?(\/|\\)|\.(\/|\\)|\.\.(\/|\\)
	 * Parts:   .*(\/|\\)\.\.?(\/|\\) - optional text followed by a forward or back slash, 
	 *                                  followed by one or two literal dots, followed
	 *                                  by a forward or back slash
	 *      OR
	 *          \.(\/|\\)             - a literal dot followed by a forward or back slash
	 *      OR 
	 *          \.\.(\/|\\)           - two literal dots followed by a forward or back slash
	 * </pre>
	 */
	private static final Pattern RELATIVE_PATHS_PATTERN =
		Pattern.compile(".*(\\/|\\\\)\\.\\.?(\\/|\\\\)|\\.(\\/|\\\\)|\\.\\.(\\/|\\\\)");

	private final LinkedHashMap<LanguageID, SleighLanguage> languages =
		new LinkedHashMap<LanguageID, SleighLanguage>();
	private final LinkedHashMap<LanguageID, SleighLanguageDescription> descriptions =
		new LinkedHashMap<LanguageID, SleighLanguageDescription>();
	private int failureCount = 0;

	public final static String LANGUAGE_DIR_NAME = "languages";

	public SleighLanguageProvider() throws Exception {
		createLanguages();
	}

	public SleighLanguageProvider(ResourceFile ldefsFile) throws Exception {
		createLanguages(ldefsFile);
	}

	private void createLanguages() throws Exception {
		Iterable<ResourceFile> files = Application.findFilesByExtensionInApplication(".ldefs");
		for (ResourceFile file : files) {
			createLanguages(file);
		}
	}

	private void createLanguages(ResourceFile file) throws Exception {
		try {
			SleighLanguageValidator.validateLdefsFile(file);
			createLanguageDescriptions(file);
		}
		catch (SleighException e) {
			++failureCount;
			Msg.showError(this, null, "Problem loading " + file.getName(),
				"Validation error: " + e.getMessage(), e);
		}
	}

	@Override
	public boolean hadLoadFailure() {
		return failureCount != 0;
	}

	@Override
	public Language getLanguage(LanguageID languageId) {
		return getNewSleigh(languageId);
	}

	@Override
	public boolean isLanguageLoaded(LanguageID languageId) {
		return languages.get(languageId) != null;
	}

	private Language getNewSleigh(LanguageID languageId) {
		SleighLanguageDescription description = descriptions.get(languageId);
		SleighLanguage lang = languages.get(languageId);
		if (lang == null) {
			try {
				lang = new SleighLanguage(description);
				languages.put(languageId, lang);
			}
			catch (SleighException e) {
				Msg.showError(this, null, "Error",
					"Can't read language spec " + description.getSlaFile().getAbsolutePath(), e);
				throw e;
			}
			catch (FileNotFoundException e) {
				Msg.showError(this, null, "Error",
					"Can't read language spec " + description.getSlaFile().getAbsolutePath(), e);
				throw new SleighException(
					"File not found - language probably did not compile properly", e);
			}
			catch (UnknownInstructionException e) {
				Msg.showError(this, null, "Error",
					"Can't read language spec " + description.getSlaFile().getAbsolutePath(), e);
				throw new SleighException(
					"Unknown instruction - language probably did not compile properly", e);
			}
			catch (SAXException e) {
				Msg.showError(this, null, "Error",
					"Can't read language spec " + description.getSlaFile().getAbsolutePath(), e);
				throw new SleighException(
					"SAXException - language probably did not compile properly", e);
			}
			catch (IOException e) {
				Msg.showError(this, null, "Error",
					"Can't read language spec " + description.getSlaFile().getAbsolutePath(), e);
				throw new SleighException(
					"IOException - language probably did not compile properly", e);
			}
		}
		return lang;
	}

	void unloadLanguage(LanguageID languageID) {
		if (languages.containsKey(languageID)) {
			languages.put(languageID, null);
		}
	}

	@Override
	public LanguageDescription[] getLanguageDescriptions() {
		LanguageDescription[] d = new LanguageDescription[descriptions.size()];
		descriptions.values().toArray(d);
		return d;
	}

	private void createLanguageDescriptions(final ResourceFile specFile) throws Exception {
		ErrorHandler errHandler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				Msg.error(SleighLanguageProvider.this, "Error parsing " + specFile, exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				Msg.error(SleighLanguageProvider.this, "Fatal error parsing " + specFile,
					exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(SleighLanguageProvider.this, "Warning parsing " + specFile, exception);
			}
		};
		XmlPullParser parser = XmlPullParserFactory.create(specFile, errHandler, false);
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
				final CompilerSpecID compilerSpecID = new CompilerSpecID(compilerID);
				final String compilerSpecName = compiler.getAttribute("name");
				final String compilerSpecFilename = compiler.getAttribute("spec");
				final ResourceFile compilerSpecFile =
					findFile(parentDirectory, compilerSpecFilename, ".cspec");
				FileResolutionResult result = existsAndIsCaseDependent(compilerSpecFile);
				if (!result.isOk()) {
					throw new SleighException("cspec file " + compilerSpecFile +
						" is not properly case dependent: " + result.getMessage());
				}
				final SleighCompilerSpecDescription sleighCompilerSpecDescription =
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
			final ResourceFile specFile = findFile(parentDirectory, pspec, ".pspec");
			result = existsAndIsCaseDependent(specFile);
			if (!result.isOk()) {
				throw new SleighException("pspec file " + specFile +
					" is not properly case dependent: " + result.getMessage());
			}
			description.setSpecFile(specFile);

			ResourceFile slaFile;
			try {
				slaFile = findFile(parentDirectory, slafilename, ".slaspec");
				result = existsAndIsCaseDependent(slaFile);
				if (!result.isOk()) {
					throw new SleighException("sla file " + slaFile +
						" is not properly case dependent: " + result.getMessage());
				}
				description.setSlaFile(slaFile);
			}
			catch (SleighException e) {
				int index = slafilename.lastIndexOf('.');
				String slabase = slafilename.substring(0, index);

				String slaspecfilename = slabase + ".slaspec";

				ResourceFile slaspecFile = findFile(parentDirectory, slaspecfilename, ".slaspec");
				result = existsAndIsCaseDependent(slaspecFile);
				if (!result.isOk()) {
					throw new SleighException("sla file source " + slaspecFile +
						" is not properly case dependent: " + result.getMessage());
				}

				slaFile = new ResourceFile(slaspecFile.getParentFile(), slafilename);
				description.setSlaFile(slaFile);
			}

			try {
				if (manualindexfile != null) {
					ResourceFile manualIndexFile =
						findFile(parentDirectory, manualindexfile, ".idx");
					result = existsAndIsCaseDependent(manualIndexFile);
					if (result.isOk()) {
						description.setManualIndexFile(manualIndexFile);
					}
					else {
						throw new SleighException(result.getMessage());
					}
				}
			}
			catch (SleighException ex) { // Error with the manual shouldn't prevent language from loading
				Msg.error(this, ex.getMessage());
			}
			if (descriptions.put(id, description) != null) {
				Msg.showError(this, null, "Duplicate Sleigh Language ID",
					"Language " + id + " previously defined: " + defsFile);
			}
		}
		parser.end(start);
	}

	private ResourceFile findFile(ResourceFile parentDir, String fileNameOrRelativePath,
			String extension) throws SleighException {
		ResourceFile file = new ResourceFile(parentDir, fileNameOrRelativePath);
		if (file.exists()) {
			return file;
		}
		String fileName = getFileNameFromPath(fileNameOrRelativePath);
		List<ResourceFile> files = findFiles(fileName, extension);
		if (files.size() == 1) {
			return files.get(0);
		}

		String relativePath = discardRelativePath(fileNameOrRelativePath);
		for (ResourceFile resourceFile : files) {
			if (file.getAbsolutePath().endsWith(relativePath)) {
				return resourceFile;
			}
		}
		ResourceFile missingFile = new ResourceFile(parentDir, fileNameOrRelativePath);
		throw new SleighException("Missing sleigh file: " + missingFile.getAbsolutePath());
	}

	private String discardRelativePath(String str) {
		return RELATIVE_PATHS_PATTERN.matcher(str).replaceFirst("");
	}

	private List<ResourceFile> findFiles(String fileName, String extension) {
		List<ResourceFile> matches = new ArrayList<ResourceFile>();
		List<ResourceFile> files = Application.findFilesByExtensionInApplication(extension);
		for (ResourceFile resourceFile : files) {
			if (resourceFile.getName().equals(fileName)) {
				matches.add(resourceFile);
			}
		}
		return matches;
	}

	private String getFileNameFromPath(String fileNameOrRelativePath) {
		int lastIndexOf = fileNameOrRelativePath.lastIndexOf("/");
		if (lastIndexOf < 0) {
			return fileNameOrRelativePath;
		}
		return fileNameOrRelativePath.substring(lastIndexOf + 1);
	}
}
