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
package ghidra.util;

import java.util.*;

import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

public interface LanguageUtilities {
	static Set<LanguageCompilerSpecPair> getAllPairsForLanguages(Set<LanguageID> languageIDs)
			throws LanguageNotFoundException {
		Set<LanguageCompilerSpecPair> result = new LinkedHashSet<>();
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		for (LanguageID lid : languageIDs) {
			Language l = langServ.getLanguage(lid);
			for (CompilerSpecDescription csd : l.getCompatibleCompilerSpecDescriptions()) {
				result.add(new LanguageCompilerSpecPair(lid, csd.getCompilerSpecID()));
			}
		}
		return result;
	}

	static Set<LanguageCompilerSpecPair> getAllPairsForLanguage(LanguageID language)
			throws LanguageNotFoundException {
		return getAllPairsForLanguages(Collections.singleton(language));
	}
}
