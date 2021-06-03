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
package ghidra.app.plugin.core.functioncompare;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.*;

import ghidra.program.model.listing.Function;

/**
 * Helper methods for use with function comparison tests
 * 
 * @see {@link CompareFunctionsTest}
 * @see {@link CompareFunctionsSlowTest}
 */
public class CompareFunctionsTestUtility {

	/**
	 * Asserts that a given list of functions represents all of the source 
	 * functions in a comparison model
	 * 
	 * @param provider the function comparison provider
	 * @param functions the source functions
	 */
	public static void checkSourceFunctions(FunctionComparisonProvider provider,
			Function... functions) {
		Set<Function> funcs = new HashSet<>(Arrays.asList(functions));
		Set<Function> fcs = provider.getModel().getSourceFunctions();
		assertEquals(fcs.size(), funcs.size());
		assertTrue(fcs.containsAll(funcs));
	}

	/**
	 * Asserts that a given function (source) is mapped to a collection of 
	 * functions (targets) in a comparison model
	 * 
	 * @param provider the function comparison provider
	 * @param source the source function
	 * @param targets the target functions
	 */
	public static void checkTargetFunctions(FunctionComparisonProvider provider,
			Function source, Function... targets) {
		Set<Function> targetsAsList = new HashSet<>(Arrays.asList(targets));
		Set<Function> tgts = provider.getModel().getTargetFunctions(source);
		assertEquals(tgts.size(), targetsAsList.size());
		assertTrue(tgts.containsAll(targetsAsList));
	}

	/**
	 * Returns the given functions as a {@link Set}
	 * 
	 * @param functions the functions to return as a set
	 * @return a set of functions
	 */
	public static Set<Function> getFunctionsAsSet(Function... functions) {
		Set<Function> set = new HashSet<>();
		set.addAll(Arrays.asList(functions));
		return set;
	}

	/**
	 * Returns the given functions as a {@link Map} of a function (source) to 
	 * a set of functions (targets)
	 * 
	 * @param source the key of the map
	 * @param targets the value of the map
	 * @return a map of a function to a set of functions
	 */
	public static Map<Function, Set<Function>> getFunctionsAsMap(Function source,
			Function... targets) {
		Set<Function> targetSet = getFunctionsAsSet(targets);
		Map<Function, Set<Function>> map = new HashMap<>();
		map.put(source, targetSet);
		return map;
	}
}
