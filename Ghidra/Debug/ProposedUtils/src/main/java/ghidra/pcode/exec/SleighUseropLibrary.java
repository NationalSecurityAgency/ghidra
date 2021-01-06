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
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.pcode.Varnode;
import ghidra.sleigh.grammar.Location;

public interface SleighUseropLibrary<T> {
	final class EmptySleighUseropLibrary implements SleighUseropLibrary<Object> {
		@Override
		public Map<String, SleighUseropDefinition<Object>> getUserops() {
			return Map.of();
		}
	}

	SleighUseropLibrary<?> NIL = new EmptySleighUseropLibrary();

	@SuppressWarnings("unchecked")
	public static <T> SleighUseropLibrary<T> nil() {
		return (SleighUseropLibrary<T>) NIL;
	}

	interface SleighUseropDefinition<T> {
		String getName();

		int getOperandCount();

		void execute(PcodeExecutorStatePiece<T, T> state, Varnode outVar, List<Varnode> inVars);
	}

	Map<String, SleighUseropDefinition<T>> getUserops();

	default SleighUseropLibrary<T> compose(SleighUseropLibrary<T> lib) {
		if (lib == null) {
			return this;
		}
		return new ComposedSleighUseropLibrary<>(List.of(this, lib));
	}

	/**
	 * Get named symbols defined by this library that are not already defined in the language
	 * 
	 * @param language the language whose existing symbols to consider
	 * @return a map of new user-op indices to extra user-op symbols
	 */
	default Map<Integer, UserOpSymbol> getSymbols(SleighLanguage language) {
		//Set<String> langDefedNames = new HashSet<>();
		Map<Integer, UserOpSymbol> symbols = new HashMap<>();
		Set<String> allNames = new HashSet<>();
		int langOpCount = language.getNumberOfUserDefinedOpNames();
		for (int i = 0; i < langOpCount; i++) {
			String name = language.getUserDefinedOpName(i);
			allNames.add(name);
		}
		int nextOpNo = langOpCount;
		for (SleighUseropDefinition<?> uop : new TreeMap<>(getUserops()).values()) {
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
		return symbols;
	}
}
