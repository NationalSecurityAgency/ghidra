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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class does the work of matching subroutines. Every subroutine
 * in the current program is hashed and the start address is put into a 
 * table. There are often identical subroutines which may have the same hash
 * value. Then the subroutines in the other program are hashed as well. All unique
 * match pairs are returned as matches. The next step would be to use call graph
 * information or address order to get additional matches. 
  */
public class MatchFunctions {
	private MatchFunctions() {
		// non-instantiable
	}

	// Finds one-to-many matches in functions from addressSet A and Address Set B
	public static List<MatchedFunctions> matchFunctions(Program aProgram, AddressSetView setA,
			Program bProgram, AddressSetView setB, int minimumFunctionSize,
			boolean includeOneToOne, boolean includeNonOneToOne, FunctionHasher hasher,
			TaskMonitor monitor) throws CancelledException {

		Map<Long, Match> functionHashes = new HashMap<>();
		List<MatchedFunctions> functionMatches = new ArrayList<MatchedFunctions>();
		FunctionIterator aProgfIter = aProgram.getFunctionManager().getFunctions(setA, true);
		FunctionIterator bProgfIter = bProgram.getFunctionManager().getFunctions(setB, true);
		monitor.setIndeterminate(false);
		monitor.initialize(2 * (aProgram.getFunctionManager().getFunctionCount() +
			bProgram.getFunctionManager().getFunctionCount()));
		monitor.setMessage("Hashing functions in " + aProgram.getName());

		// Hash functions in program A
		while (!monitor.isCancelled() && aProgfIter.hasNext()) {
			monitor.incrementProgress(1);
			Function func = aProgfIter.next();
			if (!func.isThunk() && func.getBody().getNumAddresses() >= minimumFunctionSize) {
				hashFunction(monitor, functionHashes, func, hasher, true);
			}
		}

		monitor.setMessage("Hashing functions in " + bProgram.getName());
		// Hash functions in Program B
		while (!monitor.isCancelled() && bProgfIter.hasNext()) {
			monitor.incrementProgress(1);
			Function func = bProgfIter.next();
			if (!func.isThunk() && func.getBody().getNumAddresses() >= minimumFunctionSize) {
				hashFunction(monitor, functionHashes, func, hasher, false);
			}
		}

		//Find the remaining hash matches ---> unique code match left and THERE is no symbol that matches
		//in the other program.
		final long progress = monitor.getProgress();
		monitor.setMaximum(progress + functionHashes.size());
		monitor.setProgress(progress);
		monitor.setMessage("Finding function matches");
		for (Match match : functionHashes.values()) {
			monitor.incrementProgress(1);
			if (monitor.isCancelled()) {
				break;
			}
			ArrayList<Address> aProgAddrs = match.aAddresses;
			ArrayList<Address> bProgAddrs = match.bAddresses;
			if ((includeOneToOne && aProgAddrs.size() == 1 && bProgAddrs.size() == 1) ||
				(includeNonOneToOne && !(aProgAddrs.size() == 1 && bProgAddrs.size() == 1))) {
				for (Address aAddr : aProgAddrs) {
					for (Address bAddr : bProgAddrs) {
						MatchedFunctions functionMatch =
							new MatchedFunctions(aProgram, bProgram, aAddr, bAddr,
								aProgAddrs.size(), bProgAddrs.size(), "Code Only Match");
						functionMatches.add(functionMatch);
					}
				}
			}
		}

		return functionMatches;
	}

	public static List<MatchedFunctions> matchOneFunction(Program aProgram, Address aEntryPoint,
			Program bProgram, FunctionHasher hasher, TaskMonitor monitor)
			throws CancelledException {
		return matchOneFunction(aProgram, aEntryPoint, bProgram, null, hasher, monitor);
	}

	// Finds all matches in program B to the function in Program A
	public static List<MatchedFunctions> matchOneFunction(Program aProgram, Address aEntryPoint,
			Program bProgram, AddressSetView bAddressSet, FunctionHasher hasher,
			TaskMonitor monitor)
			throws CancelledException {
		Map<Long, Match> functionHashes = new HashMap<>();
		List<MatchedFunctions> functionMatches = new ArrayList<MatchedFunctions>();

		Function aFunc = aProgram.getFunctionManager().getFunctionContaining(aEntryPoint);
		FunctionIterator bProgfIter =
			bAddressSet == null ? bProgram.getFunctionManager().getFunctions(true)
					: bProgram.getFunctionManager().getFunctions(bAddressSet, true);

		// Hash the one function in program A

		hashFunction(monitor, functionHashes, aFunc, hasher, true);

		// Hash functions in Program B
		while (!monitor.isCancelled() && bProgfIter.hasNext()) {
			Function func = bProgfIter.next();
			hashFunction(monitor, functionHashes, func, hasher, false);
		}

		//Find the remaining hash matches ---> unique code match left and THERE is no symbol that matches
		//in the other program.
		List<Long> keys = new ArrayList<>(functionHashes.keySet());
		for (long key : keys) {
			if (monitor.isCancelled()) {
				break;
			}
			Match match = functionHashes.get(key);
			ArrayList<Address> aProgAddrs = match.aAddresses;
			ArrayList<Address> bProgAddrs = match.bAddresses;

			// Want all possible matches from destination program
			if ((aProgAddrs.size() == 1) && (bProgAddrs.size() >= 1)) {
				for (int m = 0; m < bProgAddrs.size(); m++) {
					MatchedFunctions functionMatch =
						new MatchedFunctions(aProgram, bProgram, aProgAddrs.get(0),
							bProgAddrs.get(m), aProgAddrs.size(), bProgAddrs.size(),
							"Code Only Match");
					functionMatches.add(functionMatch);
				}
				functionHashes.remove(key);
			}
		}

		return functionMatches;
	}

	private static void hashFunction(TaskMonitor monitor,
			Map<Long, Match> functionHashes, Function function, FunctionHasher hasher,
			boolean isProgA) throws CancelledException {

		long hash = hasher.hash(function, monitor);

		Match subMatch = functionHashes.get(hash);
		if (subMatch == null) {
			subMatch = new Match();
			functionHashes.put(hash, subMatch);
		}
		subMatch.add(function.getEntryPoint(), isProgA);
	}

	private static class Match {
		final ArrayList<Address> aAddresses = new ArrayList<Address>();
		final ArrayList<Address> bAddresses = new ArrayList<Address>();

		public void add(Address address, boolean isProgA) {
			if (isProgA) {
				aAddresses.add(address);
			}
			else {
				bAddresses.add(address);
			}
		}
	}

	public static class MatchedFunctions {
		private final Program aProg;
		private final Program bProg;
		private final Address aAddr;
		private final Address bAddr;
		private final int aMatchNum;
		private final int bMatchNum;

		MatchedFunctions(Program aProg, Program bProg, Address aAddr, Address bAddr, int aMatchNum,
				int bMatchNum, String reason) {
			this.aProg = aProg;
			this.bProg = bProg;
			this.aAddr = aAddr;
			this.bAddr = bAddr;
			this.aMatchNum = aMatchNum;
			this.bMatchNum = bMatchNum;
		}

		public Program getAProgram() {
			return aProg;
		}

		public Program getBProgram() {
			return bProg;
		}

		public Address getAFunctionAddress() {
			return aAddr;
		}

		public Address getBFunctionAddress() {
			return bAddr;
		}

		public int getAMatchNum() {
			return aMatchNum;
		}

		public int getBMatchNum() {
			return bMatchNum;
		}
	}
}
