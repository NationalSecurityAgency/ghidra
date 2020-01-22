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

import java.util.*;

import ghidra.app.services.FunctionComparisonModel;
import ghidra.program.model.listing.Function;

/**
 * Defines the structure of a function comparison. The relationship is strictly
 * one-to-many; a single <code>source</code> function may be associated with one 
 * or more <code>target</code> functions. 
 * <p>
 * This is the basic unit for the 
 * {@link FunctionComparisonModel function comparison data model}
 */
public class FunctionComparison implements Comparable<FunctionComparison> {

	private Function source;

	/** Use a tree so functions are always kept in sorted order */
	private Set<Function> targets = new TreeSet<>(new FunctionComparator());

	/**
	 * Returns the source function
	 * 
	 * @return the source function
	 */
	public Function getSource() {
		return source;
	}

	/**
	 * Returns the set of targets, in sorted order by function name
	 * 
	 * @return the set of targets
	 */
	public Set<Function> getTargets() {
		return targets;
	}

	/**
	 * Sets a given function as the comparison source
	 * 
	 * @param function the source function
	 */
	public void setSource(Function function) {
		source = function;
	}

	/**
	 * Adds a target function to the comparison
	 * 
	 * @param function the function to add to the target list
	 */
	public void addTarget(Function function) {
		targets.add(function);
	}

	/**
	 * Adds a set of functions to the target list
	 * 
	 * @param functions the functions to add
	 */
	public void addTargets(Set<Function> functions) {
		targets.addAll(functions);
	}

	/**
	 * Removes the given function from the target list. 
	 * <p>
	 * Note that the target list is a {@link Set}, so there will only ever
	 * be at most one entry that matches the given function
	 * 
	 * @param function the function to remove
	 */
	public void removeTarget(Function function) {
		targets.remove(function);
	}

	/**
	 * Removes all targets from the comparison
	 */
	public void clearTargets() {
		targets.clear();
	}

	/**
	 * Ensures that FunctionComparison objects are always ordered according
	 * to the source function name
	 */
	@Override
	public int compareTo(FunctionComparison o) {
		if (o == null) {
			return 1;
		}
		return getSource().getName().compareTo(o.getSource().getName());
	}

	/**
	 * Forces an ordering on {@link Function} objects by name. This is 
	 * to ensure that the list of targets is kept in sorted order at all times.
	 */
	class FunctionComparator implements Comparator<Function> {

		@Override
		public int compare(Function o1, Function o2) {
			if (o1 == o2) {
				return 0;
			}
			if (o2 == null) {
				return 1;
			}
			return o1.getName().compareTo(o2.getName());
		}
	}
}
