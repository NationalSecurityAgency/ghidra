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
package ghidra.app.plugin.match;

import java.util.*;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MatchSymbol {

	private MatchSymbol() {
		// non-instantiable
	}

	public static List<MatchedSymbol> matchSymbol(Program aProgram, AddressSetView setA,
			Program bProgram, AddressSetView setB, int minSymbolNameLength,
			boolean includeOneToOneOnly, boolean includeExternals, TaskMonitor monitor)
			throws CancelledException {

		HashMap<SymbolIdentifier, Match> symbolMatches = new HashMap<>();
		List<MatchedSymbol> matchedSymbols = new ArrayList<>();

		HashMap<SymbolPath, Boolean> aUniqueSymbolPathMap = null;
		HashMap<SymbolPath, Boolean> bUniqueSymbolPathMap = null;
		if (!includeOneToOneOnly) {
			// need to keep track of exact single/unique name matches for exclusion
			aUniqueSymbolPathMap = new HashMap<>();
			bUniqueSymbolPathMap = new HashMap<>();
		}

		monitor.setIndeterminate(false);
		monitor.initialize(
			aProgram.getSymbolTable().getNumSymbols() + bProgram.getSymbolTable().getNumSymbols());

		hashSymbols(aProgram, setA, minSymbolNameLength, includeExternals, monitor,
			aUniqueSymbolPathMap, symbolMatches, true, !includeOneToOneOnly);

		hashSymbols(bProgram, setB, minSymbolNameLength, includeExternals, monitor,
			bUniqueSymbolPathMap, symbolMatches, false, !includeOneToOneOnly);

		Collection<Match> entries = symbolMatches.values();

		long progress = monitor.getProgress();

		if (includeOneToOneOnly) {
			// All items in a Match will have the same symbol path
			monitor.setMaximum(progress + symbolMatches.size());
			monitor.setProgress(progress);
			monitor.setMessage("Eliminate non-unique matches");
			Iterator<Match> matchIterator = entries.iterator();
			while (matchIterator.hasNext()) {
				monitor.incrementProgress(1);
				monitor.checkCanceled();
				Match match = matchIterator.next();
				if (match.aSymbols.size() != 1 || match.bSymbols.size() != 1) {
					// remove match if it does not contain exactly one match pair
					matchIterator.remove();
				}
			}
		}

		progress = monitor.getProgress();
		monitor.setMaximum(progress + symbolMatches.size());
		monitor.setProgress(progress);
		monitor.setMessage("Finding symbol matches");

		for (Match match : entries) {
			monitor.incrementProgress(1);
			monitor.checkCanceled();

			//TODO: special namespaces for externals - unknown, etc...
			//Library.UNKNOWN - similar to global space for normal symbols 

			Collection<SymbolIdentifier> aSymbols = match.aSymbols;
			Collection<SymbolIdentifier> bSymbols = match.bSymbols;

			for (SymbolIdentifier aSymbolIdentifier : aSymbols) {

				Boolean aHasUniqueName = null;
				if (aUniqueSymbolPathMap != null) {
					aHasUniqueName = aUniqueSymbolPathMap.get(aSymbolIdentifier.symbolPath);
				}

				for (SymbolIdentifier bSymbolIdentifier : bSymbols) {

					if (!includeOneToOneOnly) {
						if (Boolean.TRUE.equals(aHasUniqueName) &&
							aSymbolIdentifier.symbolPath.equals(bSymbolIdentifier.symbolPath) &&
							Boolean.TRUE.equals(
								bUniqueSymbolPathMap.get(bSymbolIdentifier.symbolPath))) {
							// skip one-to-one exact match when looking for duplicate matches
							// NOTE: this is still included in match count which can influence scoring
							continue;
						}
						SymbolPath aSymbolPath = aSymbolIdentifier.symbolPath;
						SymbolPath namespacePath = aSymbolPath.getParent();
						if (!aSymbolIdentifier.isExternalSymbol() && namespacePath != null &&
							!aSymbolPath.equals(bSymbolIdentifier.symbolPath) &&
							NamespaceUtils.getNonFunctionNamespace(bProgram, namespacePath) != null) {
							// skip match with namespace mismatch when source namespace exists in destination
							continue;
						}
					}

					++match.retainedMatchCount;

					MatchedSymbol symbolMatch = new MatchedSymbol(match, aProgram, bProgram,
						aSymbolIdentifier, bSymbolIdentifier);
					matchedSymbols.add(symbolMatch);
				}
			}
		}

		return matchedSymbols;

	}

	private static void hashSymbols(Program program, AddressSetView set, int minSymbolNameLength,
			boolean includeExternals, TaskMonitor monitor,
			HashMap<SymbolPath, Boolean> uniqueSymbolPathMap,
			HashMap<SymbolIdentifier, Match> symbolMatches, boolean isAProg,
			boolean ignoreNamespace) throws CancelledException {
		monitor.setMessage("Hashing symbols in " + program.getName());

		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			monitor.incrementProgress(1);
			monitor.checkCanceled();

			// Don't include default names except string ones (ie no FUN_*, LAB_*, etc... but 
			// yes s_*, u_*, etc...	
			if ((symbol.getSource() == SourceType.DEFAULT) && !isSymbolAString(program, symbol)) {
				continue;
			}

			if (symbol.getParentNamespace() instanceof Function) {
				continue; // skip local symbols
			}

			final SymbolType symbolType = symbol.getSymbolType();

			if ((symbolType == SymbolType.FUNCTION || symbolType == SymbolType.LABEL) &&
				(set.contains(symbol.getAddress()) || (symbol.isExternal() && includeExternals))) {
				String name = symbol.getName();
				if (name.length() >= minSymbolNameLength) {
					hashSymbol(uniqueSymbolPathMap, symbolMatches, symbol, isAProg,
						ignoreNamespace);
				}
			}
		}
	}

	private static void hashSymbol(HashMap<SymbolPath, Boolean> uniqueSymbolPathMap,
			HashMap<SymbolIdentifier, Match> symbolMatches, Symbol symbol, boolean isProgA,
			boolean ignoreNamespace) {
		Program program = symbol.getProgram();

		if (symbol.isExternal()) {
			ExternalLocation externalLocation =
				program.getExternalManager().getExternalLocation(symbol);
			if (externalLocation != null && hashExternalLocationOriginalName(uniqueSymbolPathMap,
				symbolMatches, externalLocation, isProgA, ignoreNamespace)) {
				// Only include original external name (i.e., mangled)
				return;
			}
		}

		SymbolPath symbolPath = new SymbolPath(symbol);
		// Get clean symbol path without address modifier
		if (!symbol.isExternal()) {
			symbolPath = getCleanSymbolPath(symbolPath, symbol.getAddress());
		}
		updateUniqueSymbolPathMap(uniqueSymbolPathMap, symbolPath);

		SymbolMatchType symbolMatchType = getSymbolMatchType(symbol);
		if (symbolMatchType == SymbolMatchType.OTHER) {
			// don't bother adding symbol
			return;
		}

		hashSymbolName(symbolMatches, symbolPath, symbolMatchType == SymbolMatchType.FUNCTION,
			ignoreNamespace, symbol.getAddress(), program, isProgA);
	}

	private enum SymbolMatchType {
		FUNCTION, DATA, OTHER;
	}

	private static SymbolMatchType getSymbolMatchType(Symbol symbol) {
		if (symbol.getSymbolType() == SymbolType.FUNCTION) {
			return SymbolMatchType.FUNCTION;
		}
		if (symbol.getSymbolType() != SymbolType.LABEL) {
			return SymbolMatchType.OTHER;
		}
		if (symbol.isExternal()) {
			return SymbolMatchType.DATA;
		}
		Listing listing = symbol.getProgram().getListing();
		if (listing.getFunctionAt(symbol.getAddress()) != null) {
			return SymbolMatchType.FUNCTION;
		}
		if (listing.getDataAt(symbol.getAddress()) != null) {
			return SymbolMatchType.DATA;
		}
		return SymbolMatchType.OTHER;
	}

	private static void updateUniqueSymbolPathMap(HashMap<SymbolPath, Boolean> uniqueSymbolPathMap,
			SymbolPath symbolPath) {
		if (uniqueSymbolPathMap == null) {
			return; // map not specified (not used for 1-to-1 matching)
		}
		Boolean hasUniqueSymbolPath = uniqueSymbolPathMap.get(symbolPath);
		if (hasUniqueSymbolPath == null) {
			uniqueSymbolPathMap.put(symbolPath, true);
		}
		else if (hasUniqueSymbolPath) {
			uniqueSymbolPathMap.put(symbolPath, false);
		}
	}

	private static boolean hashExternalLocationOriginalName(
			HashMap<SymbolPath, Boolean> uniqueSymbolPathMap,
			HashMap<SymbolIdentifier, Match> symbolMatches, ExternalLocation externalLocation,
			boolean isProgA, boolean ignoreNamespace) {
		String originalImportedName = externalLocation.getOriginalImportedName();
		if (originalImportedName != null) {
			Symbol s = externalLocation.getSymbol();
			// original name associated with library namespace only
			Library lib = NamespaceUtils.getLibrary(s.getParentNamespace());
			SymbolPath libPath = new SymbolPath(lib.getSymbol());
			SymbolPath symbolPath = new SymbolPath(libPath, originalImportedName);
			updateUniqueSymbolPathMap(uniqueSymbolPathMap, symbolPath);
			hashSymbolName(symbolMatches, symbolPath, externalLocation.isFunction(),
				ignoreNamespace, externalLocation.getExternalSpaceAddress(), s.getProgram(),
				isProgA);
			return true;
		}
		return false;
	}

	private static class SymbolIdentifier {
		final boolean isFunction; // Function or Data symbol
		final SymbolPath symbolPath;
		final Address address; // only external considered for hashCode and equals
		final boolean ignoreNamespace;

		SymbolIdentifier(SymbolPath symbolPath, Address address, boolean isFunction,
				boolean ignoreNamespace) {
			this.isFunction = isFunction;
			this.symbolPath = symbolPath;
			this.address = address;
			this.ignoreNamespace = ignoreNamespace;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + (isFunction ? 1231 : 1237);
			result = prime * result + (address.isExternalAddress() ? 1231 : 1237);
			if (ignoreNamespace) {
				result = prime * result + symbolPath.getName().hashCode();
			}
			else {
				result = prime * result + symbolPath.hashCode();
			}
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			SymbolIdentifier other = (SymbolIdentifier) obj;
			if (isFunction != other.isFunction || isExternalSymbol() != other.isExternalSymbol()) {
				return false;
			}
			if (ignoreNamespace) {
				return getName().equals(other.getName());
			}
			return symbolPath.equals(other.symbolPath);
		}

		String getName() {
			return symbolPath.getName();
		}

		boolean isMemorySymbol() {
			return address.isMemoryAddress();
		}

		boolean isExternalSymbol() {
			return address.isExternalAddress();
		}
	}

	private static SymbolPath getCleanSymbolPath(SymbolPath path, Address address) {
		if (!address.isMemoryAddress()) {
			return path;
		}
		String symbolName = path.getName();
		String cleanName = SymbolUtilities.getCleanSymbolName(symbolName, address);
		if (!cleanName.equals(symbolName)) {
			return new SymbolPath(path.getParent(), cleanName);
		}
		return path;
	}

	private static void hashSymbolName(HashMap<SymbolIdentifier, Match> symbolMatches,
			SymbolPath symbolPath, boolean isFunction, boolean ignoreNamespace, Address address,
			Program aProgram, boolean isProgA) {

		SymbolIdentifier symbolIdentifier =
			new SymbolIdentifier(symbolPath, address, isFunction, ignoreNamespace);

		Match subMatch = symbolMatches.get(symbolIdentifier);
		if (subMatch == null) {
			subMatch = new Match();
			symbolMatches.put(symbolIdentifier, subMatch);
		}
		subMatch.add(symbolIdentifier, isProgA);
	}

	private static boolean isSymbolAString(Program prog, Symbol symbol) {

		Address symAddr = symbol.getAddress();
		if (symAddr != null) {
			Data data = prog.getListing().getDataAt(symAddr);
			if ((data != null) && data.hasStringValue()) {
				return true;
			}
		}
		return false;
	}

	private static class Match {

		final List<SymbolIdentifier> aSymbols = new ArrayList<>();
		final List<SymbolIdentifier> bSymbols = new ArrayList<>();

		int retainedMatchCount;

		void add(SymbolIdentifier symbolIdentifier, boolean isProgA) {
			if (isProgA) {
				aSymbols.add(symbolIdentifier);
			}
			else {
				bSymbols.add(symbolIdentifier);
			}
		}
	}

	public static class MatchedSymbol {
		private Match match;
		private final Program aProg;
		private final Program bProg;
		private final SymbolIdentifier aSymbol;
		private final SymbolIdentifier bSymbol;

		MatchedSymbol(Match match, Program aProg, Program bProg, SymbolIdentifier aSymbol,
				SymbolIdentifier bSymbol) {
			this.match = match;
			this.aProg = aProg;
			this.bProg = bProg;
			this.aSymbol = aSymbol;
			this.bSymbol = bSymbol;
		}

		public Program getAProgram() {
			return aProg;
		}

		public Program getBProgram() {
			return bProg;
		}

		public Address getASymbolAddress() {
			return aSymbol.address;
		}

		public Address getBSymbolAddress() {
			return bSymbol.address;
		}

		public int getMatchCount() {
			return match.retainedMatchCount;
		}

		public SymbolType getMatchType() {
			return aSymbol.isFunction ? SymbolType.FUNCTION : SymbolType.LABEL;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + aSymbol.hashCode();
			result = prime * result + bSymbol.hashCode();
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			MatchedSymbol other = (MatchedSymbol) obj;
			if (match != other.match) {
				return false;
			}
			if (!SystemUtilities.isEqual(aSymbol, other.aSymbol)) {
				return false;
			}
			if (aProg != other.aProg) {
				return false;
			}
			if (!SystemUtilities.isEqual(bSymbol, other.bSymbol)) {
				return false;
			}
			if (bProg != other.bProg) {
				return false;
			}
			return true;
		}
	}
}
