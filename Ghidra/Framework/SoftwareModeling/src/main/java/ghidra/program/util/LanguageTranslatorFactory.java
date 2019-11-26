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

import java.lang.reflect.Modifier;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>LanguageTranslatorFactory</code> manages all language translators within Ghidra.  
 * Language translators support either a version translation for a single language, or a 
 * language transition from one language to another.  The following types of translators 
 * are supported:
 * <ul>
 * <li>Simple translators are established based upon a translator XML specification file (*.trans).</li>
 * <li>Explicit translators are class implementations of the LanguageTranslator interface.
 * The abstract LanguageTranslatorAdapter has been supplied for this purpose so that 
 * default mappings can be used if needed.  Such custom translator classes should not be 
 * created within the 'ghidra.program.util' package since they will be ignored by the factory.</li>
 * <li>Default translators can be instantiated for languages whose address spaces map to one-another.
 * Such default translations may be lossy with register mappings and could result in lost register 
 * variables and references.</li> 
 * </ul>
 */
public class LanguageTranslatorFactory {

	public static final String LANGUAGE_TRANSLATOR_FILE_EXT = ".trans";

	private static LanguageTranslatorFactory languageTranslatorFactory;

	private Comparator<Object> TRANSLATOR_VERSION_COMPARATOR =
		(o1, o2) -> ((LanguageTranslator) o1).getOldVersion() - ((Integer) o2).intValue();

	/**
	 * <code>translatorMap</code> provides pre-defined translators between different languages.
	 */
	private HashMap<LanguageID, List<LanguageTranslator>> translatorMap = new HashMap<>();

	/**
	 * <code>translatorVersionMap</code> provides pre-defined translators between consecutive versions 
	 * of the same language.  Lists are in sorted order based upon translator fromVersion.
	 */
	private HashMap<LanguageID, List<LanguageTranslator>> translatorVersionMap = new HashMap<>();

	private int badFileCount = 0;

	private static List<LanguageTranslatorFactoryMinion> minionList;

	public static synchronized void registerLanguageTranslatorFactoryMinion(
			LanguageTranslatorFactoryMinion minion) {
		if (minionList == null) {
			minionList = new ArrayList<>();
		}
		minionList.add(minion);
		if (languageTranslatorFactory != null) {
			languageTranslatorFactory.processMinion(minion);
		}
	}

	/**
	 * Returns the single instance of the OldLanguageFactory.
	 */
	public static LanguageTranslatorFactory getLanguageTranslatorFactory() {
		if (languageTranslatorFactory == null) {
			languageTranslatorFactory = new LanguageTranslatorFactory();
		}
		return languageTranslatorFactory;
	}

	/**
	 * Constructor.
	 */
	private LanguageTranslatorFactory() {
		initTranslatorMaps();
	}

	private void initTranslatorMaps() {
		List<LanguageTranslator> translators = new ArrayList<>();
		getSimpleTranslators(translators);
		getExplicitTranslators(translators);
		for (LanguageTranslator translator : translators) {
			addTranslator(translator);
		}
		synchronized (LanguageTranslatorFactory.class) {
			if (minionList != null) {
				for (LanguageTranslatorFactoryMinion minion : minionList) {
					processMinion(minion);
				}
			}
		}
	}

	private void addTranslator(LanguageTranslator translator) {
		if (translator.getOldLanguageID().equals(translator.getNewLanguageID())) {
			if ((translator.getOldVersion() + 1) != translator.getNewVersion()) {
				Msg.error(this,
					"Language version translator to_version same as from_version+1:\n  --> " +
						translator);
			}
			addToMap(translatorVersionMap, translator, true);
		}
		else {
			addToMap(translatorMap, translator, false);
		}
	}

	private void processMinion(LanguageTranslatorFactoryMinion minion) {
		for (LanguageTranslator translator : minion.getLanguageTranslators()) {
			addTranslator(translator);
		}
	}

	private void addToMap(HashMap<LanguageID, List<LanguageTranslator>> map,
			LanguageTranslator translator, boolean sorted) {
		LanguageID fromLanguageID = translator.getOldLanguageID();
		List<LanguageTranslator> list = map.get(fromLanguageID);
		if (list == null) {
			list = new ArrayList<>();
			map.put(fromLanguageID, list);
		}
		int index = list.size();
		if (sorted) {
			index = Collections.binarySearch(list, translator.getOldVersion(),
				TRANSLATOR_VERSION_COMPARATOR);
			if (index >= 0) {
				Msg.error(this, "Language translator conflict:\n  --> " + translator + "\n  --> " +
					list.get(index));
				return;
			}
			index = -index - 1;
		}
		list.add(index, translator);
	}

	private void getExplicitTranslators(List<LanguageTranslator> translators) {
		for (Class<?> translatorClass : ClassSearcher.getClasses(LanguageTranslator.class)) {
			int modifiers = translatorClass.getModifiers();
			if (!Modifier.isPublic(modifiers) || Modifier.isStatic(modifiers) ||
				Modifier.isAbstract(modifiers)) {
				continue; // ignore utility implementations
			}
			try {
				translators.add((LanguageTranslator) translatorClass.newInstance());
			}
			catch (Exception e) {
				Msg.error(this,
					"Failed to instatiate language translator: " + translatorClass.getName(), e);
				++badFileCount;
			}
		}
	}

	private void getSimpleTranslators(List<LanguageTranslator> list) {
		Iterable<ResourceFile> files =
			Application.findFilesByExtensionInApplication(LANGUAGE_TRANSLATOR_FILE_EXT);
		for (ResourceFile file : files) {
			try {
				list.add(SimpleLanguageTranslator.getSimpleLanguageTranslator(file));
			}
			catch (Exception e) {
				Msg.error(this, "Failed to parse: " + file, e);
				++badFileCount;
			}
		}
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
	 * Validate all translators contained within the translator maps.  
	 * This is intended to be used by a unit test.
	 * @return number of validation errors
	 */
	int validateAllTranslators() {
		int errorCnt = 0;
		for (List<LanguageTranslator> list : translatorMap.values()) {
			for (LanguageTranslator translator : list) {
				if (!translator.isValid()) {
					++errorCnt;
				}
			}
		}
		for (List<LanguageTranslator> list : translatorVersionMap.values()) {
			for (LanguageTranslator translator : list) {
				if (!translator.isValid()) {
					++errorCnt;
				}
			}
		}
		return errorCnt;
	}

	/**
	 * Returns a list of all translators.
	 */
	List<LanguageTranslator> getAllTranslators() {
		List<LanguageTranslator> list = new ArrayList<>();
		for (List<LanguageTranslator> tlist : translatorMap.values()) {
			list.addAll(tlist);
		}
		for (List<LanguageTranslator> tlist : translatorVersionMap.values()) {
			list.addAll(tlist);
		}
		return list;
	}

	/**
	 * Returns a language translator for the transition from an oldLanguage to a newLanguage.
	 * The toLanguage may be a different language or a newer version of fromLanguage.
	 * @param fromLanguage old language
	 * @param toLanguage new language
	 * @return language translator if transition is supported, otherwise null is returned.
	 */
	public LanguageTranslator getLanguageTranslator(Language fromLanguage, Language toLanguage) {
		if (toLanguage instanceof OldLanguage) {
			throw new IllegalArgumentException("toLanguage instanceof OldLanguage");
		}
		int fromVersion = fromLanguage.getVersion();
		int toVersion = toLanguage.getVersion();

		if (fromLanguage.getLanguageID().equals(toLanguage.getLanguageID())) {
			// Handle version change
			if (fromVersion >= toVersion) {
				throw new IllegalArgumentException("language from-version >= to-version");
			}
			return getLanguageVersionTranslator(fromLanguage.getLanguageID(), fromVersion,
				toVersion);
		}

		// Handle language change
		List<LanguageTranslator> languageTranslatorList =
			translatorMap.get(fromLanguage.getLanguageID());
		if (languageTranslatorList != null) {
			for (LanguageTranslator translator : languageTranslatorList) {
				if (translator.getOldVersion() < fromVersion ||
					!toLanguage.getLanguageID().equals(translator.getNewLanguageID())) {
					continue;
				}
				translator = expandTranslator(translator, fromVersion);
				if (translator != null) {
					return translator;
				}
			}
		}
		return LanguageTranslatorAdapter.getDefaultLanguageTranslator(fromLanguage, toLanguage);
	}

	/**
	 * Returns a language translation for a language version which is no longer supported.
	 * @param languageName old unsupported language name
	 * @param majorVersion language major version within program
	 * @return language translator if one can be determined, otherwise null is returned.
	 */
	public LanguageTranslator getLanguageTranslator(LanguageID languageName, int majorVersion) {
		List<LanguageTranslator> languageTranslatorList = translatorMap.get(languageName);
		if (languageTranslatorList == null) {
			return null;
		}
		for (LanguageTranslator translator : languageTranslatorList) {
			if (translator.getOldVersion() < majorVersion) {
				continue;
			}
			translator = expandTranslator(translator, majorVersion);
			if (translator != null) {
				return translator;
			}
		}
		return null;
	}

	/**
	 * Expand the to/from sides of a language translator to originate "from" the specified 
	 * fromMajorVersion and terminate at the current version of the "to" language. 
	 * @param translator
	 * @param fromVersion
	 * @return expanded translator or null if it could not be filled-out completely
	 */
	@SuppressWarnings("null")
	private LanguageTranslator expandTranslator(LanguageTranslator translator, int fromVersion) {

		Language toLanguage;
		try {
			LanguageID languageId = translator.getNewLanguageID();
			toLanguage = DefaultLanguageService.getLanguageService().getLanguage(languageId);
		}
		catch (LanguageNotFoundException e) {
			Msg.error(this, "Invalid translator - language not found: " + translator);
			return null;
		}
		int toVersion = toLanguage.getVersion();

		if (translator.getOldVersion() != fromVersion) {
			LanguageTranslator expandedFromTranslator = getLanguageVersionTranslator(
				translator.getOldLanguageID(), fromVersion, translator.getOldVersion());
			if (expandedFromTranslator == null) {
				return null; // could not build version translator
			}
			translator = new FactoryLanguageTranslator(expandedFromTranslator, translator);
		}

		if (translator.getNewVersion() != toVersion) {
			LanguageTranslator expandedFromTranslator = getLanguageVersionTranslator(
				translator.getNewLanguageID(), translator.getNewVersion(), toVersion);
			if (expandedFromTranslator == null) {
				return null; // could not build version translator
			}
			translator = new FactoryLanguageTranslator(translator, expandedFromTranslator);
		}

		if (translator != null && !translator.isValid()) {
			translator = null;
		}

		return translator;
	}

	/**
	 * Build language version translator.  A default translator will be built if 
	 * explicit translators have not been defined.
	 * @param languageID
	 * @param fromVersion
	 * @param toVersion
	 * @return language translator or null if one could not be built
	 */
	private LanguageTranslator getLanguageVersionTranslator(LanguageID languageID, int fromVersion,
			int toVersion) {

		List<LanguageTranslator> list = translatorVersionMap.get(languageID);
		if (list == null) {
			return null;
		}

		LanguageTranslator translator = null;
		int version = fromVersion;
		while (version < toVersion) {

			LanguageTranslator nextTranslator = getNextTranslator(list, version);
			if (nextTranslator == null || nextTranslator.getNewVersion() > toVersion) {
				// explicit translator not found - try using default translator
				nextTranslator = LanguageTranslatorAdapter.getDefaultLanguageTranslator(languageID,
					version, toVersion);
				if (nextTranslator == null) {
					return null; // could not build default translator
				}
			}
			if (version == nextTranslator.getNewVersion()) {
				Msg.error(this, "Invalid language translator: " + nextTranslator);
				return null;
			}
			if (version != nextTranslator.getOldVersion()) {
				// fill-in translator gap with default translator
				LanguageTranslator gapTranslator =
					LanguageTranslatorAdapter.getDefaultLanguageTranslator(languageID, version,
						nextTranslator.getOldVersion());
				if (gapTranslator == null) {
					return null; // could not build default translator
				}
				nextTranslator = new FactoryLanguageTranslator(gapTranslator, nextTranslator);
			}
			if (translator != null) {
				translator = new FactoryLanguageTranslator(translator, nextTranslator);
			}
			else {
				translator = nextTranslator;
			}
			version = nextTranslator.getNewVersion();
		}

		if (translator != null && !translator.isValid()) {
			translator = null;
		}

		return translator;
	}

	/**
	 * 
	 * @param versionTranslatorList sorted list of version translators
	 * @param version
	 * @return
	 */
	private LanguageTranslator getNextTranslator(List<LanguageTranslator> versionTranslatorList,
			int version) {
		int index =
			Collections.binarySearch(versionTranslatorList, version, TRANSLATOR_VERSION_COMPARATOR);
		if (index < 0) {
			index = -index - 1;
		}
		if (index < versionTranslatorList.size()) {
			return versionTranslatorList.get(index);
		}
		return null;
	}
}

class FactoryLanguageTranslator implements LanguageTranslator {

	// OLD -> t1 -> t2 -> NEW
	private final LanguageTranslator t1;
	private final LanguageTranslator t2;

	FactoryLanguageTranslator(LanguageTranslator t1, LanguageTranslator t2) {
		this.t1 = t1;
		this.t2 = t2;
	}

	@Override
	public Language getNewLanguage() {
		return t2.getNewLanguage();
	}

	@Override
	public Language getOldLanguage() {
		return t1.getOldLanguage();
	}

	@Override
	public Register getOldRegister(Address oldAddr, int size) {
		return t1.getOldRegister(oldAddr, size);
	}

	@Override
	public Register getOldRegisterContaining(Address oldAddr) {
		return t1.getOldRegisterContaining(oldAddr);
	}

	@Override
	public Register getOldContextRegister() {
		return t1.getOldContextRegister();
	}

	@Override
	public Register getNewContextRegister() {
		return t2.getNewContextRegister();
	}

	@Override
	public Register getNewRegister(Register oldReg) {
		Register reg = t1.getNewRegister(oldReg);
		if (reg != null) {
			return t2.getNewRegister(reg);
		}
		return null;
	}

//	public Register getOldRegister(Register newReg) {
//		Register reg = t2.getOldRegister(newReg);
//		if (reg != null) {
//			return t1.getOldRegister(reg);
//		}
//		return null;
//	}

	@Override
	public AddressSpace getNewAddressSpace(String oldSpaceName) {
		AddressSpace space = t1.getNewAddressSpace(oldSpaceName);
		if (space != null) {
			return t2.getNewAddressSpace(space.getName());
		}
		return null;
	}

	@Override
	public LanguageID getOldLanguageID() {
		return t1.getOldLanguageID();
	}

	@Override
	public int getOldVersion() {
		return t1.getOldVersion();
	}

	@Override
	public LanguageID getNewLanguageID() {
		return t2.getNewLanguageID();
	}

	@Override
	public int getNewVersion() {
		return t2.getNewVersion();
	}

	@Override
	public boolean isValueTranslationRequired(Register oldReg) {
		Register reg = t1.getNewRegister(oldReg);
		if (reg == null) {
			return false;
		}
		return t2.isValueTranslationRequired(reg) || t1.isValueTranslationRequired(oldReg);
	}

	@Override
	public RegisterValue getNewRegisterValue(RegisterValue oldRegValue) {
		RegisterValue newVal = t1.getNewRegisterValue(oldRegValue);
		if (newVal == null) {
			Register reg = t1.getNewRegister(oldRegValue.getRegister());
			if (reg == null) {
				return null;
			}
			newVal = new RegisterValue(reg);
		}
		return t2.getNewRegisterValue(newVal);
	}

	@Override
	public boolean isValid() {
		return t1.isValid() && t2.isValid();
	}

	@Override
	public CompilerSpecID getNewCompilerSpecID(CompilerSpecID oldCompilerSpecID) {
		CompilerSpecID specId = t1.getNewCompilerSpecID(oldCompilerSpecID);
		return t2.getNewCompilerSpecID(specId);
	}

	@Override
	public CompilerSpec getOldCompilerSpec(CompilerSpecID oldCompilerSpecID)
			throws CompilerSpecNotFoundException {
		return new TemporaryCompilerSpec(this, oldCompilerSpecID);
	}

	@Override
	public void fixupInstructions(Program program, Language oldLanguage, TaskMonitor monitor)
			throws Exception, CancelledException {
		// only the latest fixup is invoked
		t2.fixupInstructions(program, oldLanguage, monitor);
	}

	@Override
	public String toString() {
		return t1.toString() + "; " + System.getProperty("line.separator") + t2.toString();
	}
}
