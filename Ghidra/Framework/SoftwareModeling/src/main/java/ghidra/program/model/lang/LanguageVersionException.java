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

import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;

public class LanguageVersionException extends VersionException {

	private Language oldLanguage;
	private LanguageTranslator languageTranslator;

	/**
	 * Construct a language version exception
	 * @param msg condition detail
	 * @param upgradable true indicates that an upgrade is possible.
	 */
	public LanguageVersionException(String msg, boolean upgradable) {
		super(msg, upgradable ? OLDER_VERSION : UNKNOWN_VERSION, upgradable);
	}

	/**
	 * Construct a major upgradeable language version exception
	 * @param oldLanguage old language stub
	 * @param languageTranslator language transalator
	 */
	public LanguageVersionException(Language oldLanguage,
			LanguageTranslator languageTranslator) {
		super(true);
		this.oldLanguage = oldLanguage;
		this.languageTranslator = languageTranslator;
	}

	/**
	 * Old language stub if language translation required
	 * @return Old language stub or null
	 */
	public Language getOldLanguage() {
		return oldLanguage;
	}

	/**
	 * Old language upgrade translator if language translation required
	 * @return language upgrade translator or null
	 */
	public LanguageTranslator getLanguageTranslator() {
		return languageTranslator;
	}

	/**
	 * Check language against required version information.  If not a match or upgradeable
	 * a {@link LanguageNotFoundException} will be thrown.  If an upgradeable {@link LanguageVersionException}
	 * is returned, a major version change will also include the appropriate Old-Language stub and
	 * {@link LanguageTranslator} required to facilitate a language upgrade.
	 * @param language language corresponding to desired language ID
	 * @param languageVersion required major language version
	 * @param languageMinorVersion required minor language version.  A negative minor version will be ignored.
	 * @return null if language matches, otherwise an upgradeable {@link LanguageVersionException}.
	 * @throws LanguageNotFoundException if language is a mismatch and is not upgradeable.
	 */
	public static LanguageVersionException check(Language language, int languageVersion,
			int languageMinorVersion) throws LanguageNotFoundException {

		LanguageID languageID = language.getLanguageID();

		if (language.getVersion() > languageVersion) {

			Language newLanguage = language;

			Language oldLanguage = OldLanguageFactory.getOldLanguageFactory()
					.getOldLanguage(languageID, languageVersion);
			if (oldLanguage == null) {
				// old language does not exist to facilitate upgrade translation
				String msg = "Old language specification not found: " + languageID + " (Version " +
					languageVersion + "), translation not possible";
				Msg.error(LanguageVersionException.class, msg);
				return new LanguageVersionException(msg, false);
			}

			// Ensure that we can upgrade the language
			LanguageTranslator languageUpgradeTranslator =
				LanguageTranslatorFactory.getLanguageTranslatorFactory()
						.getLanguageTranslator(oldLanguage, newLanguage);
			if (languageUpgradeTranslator == null) {

// TODO: This is a bad situation!! Most language revisions should be supportable, if not we have no choice but to throw 
// a LanguageNotFoundException  until we figure out how to deal with nasty translations which require
// a complete redisassembly and possibly auto analysis.

				throw new LanguageNotFoundException(language.getLanguageID(),
					"(Ver " + languageVersion + "." + languageMinorVersion + " -> " +
						newLanguage.getVersion() + "." + newLanguage.getMinorVersion() +
						") language version translation not supported");
			}
			language = oldLanguage;
			return new LanguageVersionException(oldLanguage, languageUpgradeTranslator);
		}
		else if (language.getVersion() == languageVersion && languageMinorVersion < 0) {
			// Minor version ignored - considered as match if major number matches
			return null;
		}
		else if (language.getVersion() == languageVersion &&
			language.getMinorVersion() > languageMinorVersion) {
			// Minor version change - translator not needed (languageUpgradeTranslator is null)
			String fromVer = languageVersion + "." + languageMinorVersion;
			String toVer = languageVersion + "." + language.getMinorVersion();
			return new LanguageVersionException("Minor language change " + fromVer + " -> " + toVer,
				true);
		}
		else if (language.getMinorVersion() != languageMinorVersion ||
			language.getVersion() != languageVersion) {
			throw new LanguageNotFoundException(language.getLanguageID(), languageVersion,
				languageMinorVersion);
		}
		return null; // language matches
	}

	/**
	 * Determine if a missing language resulting in a {@link LanguageNotFoundException} can be 
	 * upgraded to a replacement language via a language translation.
	 * @param e original {@link LanguageNotFoundException}
	 * @param languageID language ID of original language requested
	 * @param languageVersion original language major version
	 * @return upgradeable {@link LanguageVersionException}
	 * @throws LanguageNotFoundException original exception if a language transaltion is not available
	 */
	public static LanguageVersionException checkForLanguageChange(LanguageNotFoundException e,
			LanguageID languageID, int languageVersion) throws LanguageNotFoundException {

		LanguageTranslator languageUpgradeTranslator =
			LanguageTranslatorFactory.getLanguageTranslatorFactory()
					.getLanguageTranslator(languageID, languageVersion);
		if (languageUpgradeTranslator == null) {
			throw e;
		}

		Language oldLanguage = languageUpgradeTranslator.getOldLanguage();
		LanguageID oldLanguageID = oldLanguage.getLanguageID();

		LanguageVersionException ve =
			new LanguageVersionException(oldLanguage, languageUpgradeTranslator);
		LanguageID newLangName = languageUpgradeTranslator.getNewLanguage().getLanguageID();
		String message;
		if (oldLanguageID.equals(newLangName)) {
			message = "Program requires a processor language version change";
		}
		else {
			message = "Program requires a processor language change to: " + newLangName;
		}
		ve.setDetailMessage(message);
		return ve;
	}

}
