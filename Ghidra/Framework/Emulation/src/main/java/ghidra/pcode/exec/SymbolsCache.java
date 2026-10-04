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
package ghidra.pcode.exec;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropSymbolMap;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.sleigh.grammar.Location;

class SymbolsCache {
	private final PcodeUseropLibrary<?> library;
	private final Map<SleighLanguage, PcodeUseropSymbolMap> cache = new HashMap<>();

	public SymbolsCache(PcodeUseropLibrary<?> library) {
		this.library = library;
	}

	PcodeUseropSymbolMap computeSymbols(SleighLanguage language) {
		Map<Integer, UserOpSymbol> symbols = new HashMap<>();
		Set<String> allNames = new HashSet<>();
		int langOpCount = language.getNumberOfUserDefinedOpNames();
		for (int i = 0; i < langOpCount; i++) {
			String name = language.getUserDefinedOpName(i);
			allNames.add(name);
		}
		int nextOpNo = langOpCount;
		for (PcodeUseropDefinition<?> uop : new TreeMap<>(library.getUserops()).values()) {
			String opName = uop.getName();
			if (!allNames.add(opName)) {
				// Real duplicates will cause a warning during execution
				continue;
			}

			int opNo = nextOpNo++;
			Location loc = new Location(getClass().getName() + ":" + opName, 0);
			UserOpSymbol sym = new UserOpSymbol(loc, opName);
			sym.setIndex(opNo);
			symbols.put(opNo, sym);
		}
		return new PcodeUseropSymbolMap(language, Collections.unmodifiableMap(symbols));
	}

	PcodeUseropSymbolMap getSymbols(SleighLanguage language) {
		synchronized (cache) {
			return cache.computeIfAbsent(language, this::computeSymbols);
		}
	}
}
