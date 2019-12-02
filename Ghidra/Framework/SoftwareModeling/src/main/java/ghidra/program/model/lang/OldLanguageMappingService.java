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
package ghidra.program.model.lang;

import ghidra.framework.PluggableServiceRegistry;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;

public class OldLanguageMappingService {
	static {
		PluggableServiceRegistry.registerPluggableService(OldLanguageMappingService.class,
			new OldLanguageMappingService());
	}

	/**
	 * Check for a mapping of an old language-name magicString to a LanguageID/CompilerSpec pair.
	 * If returnLanguageReplacement is false, the returned LanguageID/CompilerSpec pair may no 
	 * longer exist and may require use of an OldLanguage and translation process.
	 * @param magicString old language name magic string
	 * @param languageReplacementOK if true the LanguageID/CompilerSpec pair corresponding to the
	 * latest language implementation will be returned if found, otherwise the a deprecated LanguageID/CompilerSpec pair
	 * may be returned.  This parameter should be false if there is a sensitivity to the language implementation 
	 * (e.g., instruction prototypes, etc.)
	 * @return LanguageID/CompilerSpec pair or null if entry not found.
	 */
	public static LanguageCompilerSpecPair lookupMagicString(String magicString,
			boolean languageReplacementOK) {
		OldLanguageMappingService factory =
			PluggableServiceRegistry.getPluggableService(OldLanguageMappingService.class);
		return factory.doLookupMagicString(magicString, languageReplacementOK);
	}

	protected LanguageCompilerSpecPair doLookupMagicString(String magicString,
			boolean languageReplacementOK) {
		return null;
	}

	protected static LanguageCompilerSpecPair validatePair(LanguageCompilerSpecPair pair) {
		try {
			Language lang =
				DefaultLanguageService.getLanguageService().getLanguage(pair.languageID);
			try {
				lang.getCompilerSpecByID(pair.compilerSpecID);
				return pair;
			}
			catch (CompilerSpecNotFoundException e) {
				Msg.warn(OldLanguageMappingService.class, "Compiler spec not found: " +
					pair.languageID + "->" + pair.compilerSpecID);
			}
			return new LanguageCompilerSpecPair(pair.languageID,
				lang.getDefaultCompilerSpec().getCompilerSpecID());
		}
		catch (LanguageNotFoundException lnfe) {
			Msg.warn(OldLanguageMappingService.class, "Language not found: " + pair.languageID);
		}
		return null;
	}

	/**
	 * Parse the language string from an XML language name into the most appropriate LanguageID/CompilerSpec pair.
	 * The language name may either be an old name (i.e., magicString) or a new {@code <language-id>:<compiler-spec-id>} string.
	 * If an old language name magic-string is provided, its replacement language will be returned if known.
	 * The returned pair may or may not be available based upon available language implementations.
	 * @param languageString old or new language string
	 * @return LanguageID/CompilerSpec pair or null if no old name mapping could be found.
	 */
	public static LanguageCompilerSpecPair processXmlLanguageString(String languageString) {
		if (languageString == null) {
			return null;        // XML file didn't specify a specific language, nothing to do
		}

		// look for new mangled languageID and compilerSpecID  ( languageID + ":" + compilerSpecID );
		int index = languageString.lastIndexOf(':');
		if (index > 0) {
			LanguageCompilerSpecPair pair =
				new LanguageCompilerSpecPair(new LanguageID(languageString.substring(0, index)),
					new CompilerSpecID(languageString.substring(index + 1)));
			return OldLanguageMappingService.validatePair(pair);  // may alter compiler spec
		}
		return lookupMagicString(languageString, true);
	}
}
