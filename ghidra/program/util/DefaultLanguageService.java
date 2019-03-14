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

import java.util.*;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.program.model.lang.*;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Default Language service used gather up all the languages that were found
 * during the class search (search was for language providers)
 */
public class DefaultLanguageService implements LanguageService, ChangeListener {
	private static final Logger log = LogManager.getLogger(DefaultLanguageService.class);

	private List<LanguageInfo> languageInfos = new ArrayList<>();
	private HashMap<LanguageID, LanguageInfo> languageMap = new HashMap<>();
	private boolean searchCompleted = false;

	private static DefaultLanguageService languageService;

	/**
	 * Returns the single instance of the DefaultLanguageService.
	 */
	public static synchronized LanguageService getLanguageService() {
		if (languageService == null) {
			languageService = new DefaultLanguageService();
		}
		else if (!languageService.searchCompleted) {
			languageService.searchForProviders();
		}
		return languageService;
	}

	/**
	 * Return the single instance of the DefaultLanguageService.  If not already
	 * instantiated in the default mode, the factory will be lazy and limit 
	 * it set of languages to those defined by the specified Sleigh language definition
	 * file (*.ldefs) or those provided by subsequent calls to this method.
	 * @param sleighLdefsFile sleigh language definition file
	 * @return language factory instance
	 * @throws Exception if an error occurs while parsing the specified definition file
	 */
	public static synchronized LanguageService getLanguageService(ResourceFile sleighLdefsFile)
			throws Exception {
		SleighLanguageProvider provider = new SleighLanguageProvider(sleighLdefsFile);
		if (languageService == null) {
			languageService = new DefaultLanguageService(provider);
		}
		languageService.addLanguages(provider);
		return languageService;
	}

	private DefaultLanguageService() {
		searchForProviders();
		ClassSearcher.addChangeListener(this);
	}

	private DefaultLanguageService(LanguageProvider provider) {
		addLanguages(provider);
	}

	private void searchForProviders() {
		Set<LanguageProvider> languageProviders =
			ClassSearcher.getInstances(LanguageProvider.class);
		searchCompleted = true;
		processProviders(languageProviders);
	}

	/**
	 * @see ghidra.program.model.lang.LanguageService#getLanguage(ghidra.program.model.lang.LanguageID)
	 */
	@Override
	public Language getLanguage(LanguageID languageID) throws LanguageNotFoundException {
		LanguageInfo info = languageMap.get(languageID);

		if (info == null) {
			throw new LanguageNotFoundException(languageID);
		}

		return info.getLanguage();
	}

	/**
	 * @see ghidra.program.model.lang.LanguageService#getLanguageDescription(ghidra.program.model.lang.LanguageID)
	 */
	@Override
	public LanguageDescription getLanguageDescription(LanguageID languageID)
			throws LanguageNotFoundException {
		LanguageInfo info = languageMap.get(languageID);
		if (info == null) {
			throw new LanguageNotFoundException(languageID);
		}
		return info.ld;
	}

	/**
	 * @see ghidra.program.model.lang.LanguageService#getLanguageDescriptions(boolean)
	 */
	@Override
	public List<LanguageDescription> getLanguageDescriptions(boolean includeDeprecatedLanguages) {
		List<LanguageDescription> languageDescriptions = new ArrayList<>();
		for (LanguageInfo info : languageInfos) {
			if (includeDeprecatedLanguages || !info.ld.isDeprecated()) {
				languageDescriptions.add(info.ld);
			}
		}
		return languageDescriptions;
	}

	/**
	 * @see ghidra.program.model.lang.LanguageService#getLanguageDescriptions(ghidra.program.model.lang.Processor,
	 *      ghidra.program.model.lang.Endian, java.lang.Integer,
	 *      java.lang.String)
	 */
	@Override
	public List<LanguageDescription> getLanguageDescriptions(Processor processor, Endian endianess,
			Integer size, String variant) {
		List<LanguageDescription> languageDescriptions = new ArrayList<>();
		for (LanguageInfo info : languageInfos) {
			LanguageDescription description = info.ld;
			if (processor != null && processor != description.getProcessor()) {
				continue;
			}
			if (endianess != null && endianess != description.getEndian()) {
				continue;
			}
			if (size != null && size.intValue() != description.getSize()) {
				continue;
			}
			if (variant != null && !variant.equals(description.getVariant())) {
				continue;
			}
			languageDescriptions.add(description);
		}
		return languageDescriptions;
	}

	private static boolean languageMatchesExternalProcessor(LanguageDescription description,
			String externalProcessorName, String externalTool) {
		boolean result = false;
		if (externalProcessorName == null)
			result = true;
		else if (externalTool != null) {
			List<String> extNames = description.getExternalNames(externalTool);
			if (extNames != null) {
				for (String extName : extNames) {
					if (externalProcessorName.equalsIgnoreCase(extName)) {
						result = true;
						break;
					}
				}
			}
		}
		return result;
	}

	public List<LanguageDescription> getExternalLanguageDescriptions(String externalProcessorName,
			String externalTool, Endian endianess, Integer size) {

		List<LanguageDescription> languageDescriptions = new ArrayList<>();
		for (LanguageInfo info : languageInfos) {
			LanguageDescription description = info.ld;

			if (!languageMatchesExternalProcessor(description, externalProcessorName,
				externalTool)) {
				continue;
			}

			if (endianess != null && endianess != description.getEndian()) {
				continue;
			}
			if (size != null && size.intValue() != description.getSize()) {
				continue;
			}

			languageDescriptions.add(description);
		}
		return languageDescriptions;
	}

	@Override
	public List<LanguageCompilerSpecPair> getLanguageCompilerSpecPairs(
			LanguageCompilerSpecQuery query) {
		List<LanguageCompilerSpecPair> result = new ArrayList<>();
		List<LanguageDescription> languageDescriptions =
			getLanguageDescriptions(query.processor, query.endian, query.size, query.variant);
		for (LanguageDescription languageDescription : languageDescriptions) {
			if (!languageDescription.isDeprecated()) {
				Collection<CompilerSpecDescription> compilerSpecDescriptions =
					languageDescription.getCompatibleCompilerSpecDescriptions();
				for (CompilerSpecDescription compilerSpecDescription : compilerSpecDescriptions) {
					if (query.compilerSpecID == null ||
						query.compilerSpecID.equals(compilerSpecDescription.getCompilerSpecID())) {
						result.add(new LanguageCompilerSpecPair(languageDescription.getLanguageID(),
							compilerSpecDescription.getCompilerSpecID()));
					}
				}
			}
		}
		return result;
	}

	@Override
	public List<LanguageCompilerSpecPair> getLanguageCompilerSpecPairs(
			ExternalLanguageCompilerSpecQuery query) {
		List<LanguageCompilerSpecPair> result = new ArrayList<>();
		List<LanguageDescription> languageDescriptions = getExternalLanguageDescriptions(
			query.externalProcessorName, query.externalTool, query.endian, query.size);
		for (LanguageDescription languageDescription : languageDescriptions) {
			if (!languageDescription.isDeprecated()) {
				addLanguageCompilerSpecPairs(languageDescription, query.compilerSpecID, result);
			}
		}
		return result;
	}

	/**
	 * Check all compiler specs associated with the specified
	 * languageDescription for one that matches the specified
	 * preferredCompilerSpecId. If no match is found or preferredCompilerSpecId
	 * is null all available compiler spec pairs will be added allowing the user
	 * to choose one. This method will always add a minimum of one pair to the
	 * result.
	 * 
	 * @param languageDescription
	 *            language description
	 * @param preferredCompilerSpecId
	 *            preferred compiler spec ID or null
	 * @param result
	 *            list to which language / compile-spec pairs will be added.
	 */
	private void addLanguageCompilerSpecPairs(LanguageDescription languageDescription,
			CompilerSpecID preferredCompilerSpecId, List<LanguageCompilerSpecPair> result) {
		Collection<CompilerSpecDescription> compilerSpecDescriptions =
			languageDescription.getCompatibleCompilerSpecDescriptions();

		if (preferredCompilerSpecId != null) {
			// look for exact cspec match
			for (CompilerSpecDescription compilerSpecDescription : compilerSpecDescriptions) {
				if (preferredCompilerSpecId.equals(compilerSpecDescription.getCompilerSpecID())) {
					result.add(new LanguageCompilerSpecPair(languageDescription.getLanguageID(),
						compilerSpecDescription.getCompilerSpecID()));
					return;
				}
			}
		}

		// exact match not found - add all cspecs
		for (CompilerSpecDescription compilerSpecDescription : compilerSpecDescriptions) {
			result.add(new LanguageCompilerSpecPair(languageDescription.getLanguageID(),
				compilerSpecDescription.getCompilerSpecID()));
		}

	}

	/**
	 * @see ghidra.program.model.lang.LanguageService#getLanguageDescriptions(ghidra.program.model.lang.Processor)
	 */
	@Override
	public List<LanguageDescription> getLanguageDescriptions(Processor processor) {
		ArrayList<LanguageDescription> list = new ArrayList<>();

		for (LanguageInfo info : languageInfos) {
			if (info.ld.getProcessor().equals(processor)) {
				list.add(info.ld);
			}
		}
		return list;
	}

	/**
	 * Returns external names for specified language associated with other
	 * tools. For example, x86 languages are usually referred to as "metapc" by
	 * IDA-PRO.
	 *
	 * @param languageId
	 *            language to search against
	 * @param tool
	 *            name of external tool to search against
	 * @param includeDeprecated
	 *            include deprecated LanguageDescriptions
	 * @return external names for this language associated with tool
	 */
	public static List<String> getDefinedExternalToolNames(String languageId, String tool,
			boolean includeDeprecated) {
		List<String> returnValue = null;
		if (languageId != null && languageId.length() > 0 && tool != null && tool.length() > 0) {
			List<LanguageDescription> languageDescriptions =
				DefaultLanguageService.getLanguageService().getLanguageDescriptions(
					includeDeprecated);
			if (languageDescriptions != null) {
				for (LanguageDescription ld : languageDescriptions) {
					if (ld != null && languageId.equals(ld.getLanguageID().toString())) {
						List<String> externalNames = ld.getExternalNames(tool);
						if (externalNames != null) {
							returnValue = externalNames;
							break;
						}
					}
				}
			}
		}
		return returnValue;
	}

	/**
	 * @see ghidra.program.model.lang.LanguageService#getDefaultLanguage(ghidra.program.model.lang.Processor)
	 */
	@Override
	public Language getDefaultLanguage(Processor processor) throws LanguageNotFoundException {
		if (processor == null) {
			throw new IllegalArgumentException("processor == null not allowed");
		}
		for (LanguageInfo info : languageInfos) {
			if (info.ld.getProcessor().equals(processor)) {
				long start = System.currentTimeMillis();
				Language language = info.getLanguage();
				log.debug("getDefaultLanguage(" + language.getLanguageID() + ") took " +
					(System.currentTimeMillis() - start) + " ms");
				return language;
			}
		}
		throw new LanguageNotFoundException(processor);
	}

	private void processProviders(Set<LanguageProvider> providers) {
		for (LanguageProvider provider : providers) {
			addLanguages(provider);
		}
	}

	private void addLanguages(LanguageProvider provider) {
		LanguageDescription[] lds = provider.getLanguageDescriptions();
		for (LanguageDescription description : lds) {
			LanguageInfo info = new LanguageInfo(description, provider);
			if (languageInfos.contains(info)) {
				// skip language previously added
				continue;
			}
			languageInfos.add(info);
			LanguageID id = info.ld.getLanguageID();
			if (languageMap.containsKey(id)) {
				throw new IllegalStateException("Duplicate language ID encountered: " + id);
			}
			languageMap.put(id, info);
		}
	}

	class LanguageInfo {
		LanguageDescription ld;
		LanguageProvider lp;

		LanguageInfo(LanguageDescription ld, LanguageProvider lp) {
			this.ld = ld;
			this.lp = lp;
		}

		Language getLanguage() {
			return lp.getLanguage(ld.getLanguageID());
		}

		@Override
		public String toString() {
			return ld.getLanguageID().getIdAsString();
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof LanguageInfo)) {
				return false;
			}
			LanguageInfo otherInfo = (LanguageInfo) obj;
			return ld.getLanguageID().equals(otherInfo.ld.getLanguageID());
		}

		@Override
		public int hashCode() {
			return ld.getLanguageID().hashCode();
		}
	}

	/**
	 * @see javax.swing.event.ChangeListener#stateChanged(javax.swing.event.ChangeEvent)
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		// NOTE: this is only intended to pickup new language providers 
		// which is not really supported with the introduction of Sleigh.
		searchForProviders();
	}
}
