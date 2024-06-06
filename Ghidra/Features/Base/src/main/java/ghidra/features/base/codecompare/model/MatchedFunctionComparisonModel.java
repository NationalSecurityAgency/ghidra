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
/**
 * 
 */
package ghidra.features.base.codecompare.model;

import static ghidra.util.datastruct.Duo.Side.*;

import java.util.*;
import java.util.Map.Entry;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/**
 * A FunctionComparisonModel comprised of matched pairs of source and target functions. Each
 * source function has its own set of target functions that it can be compared with.
 */
public class MatchedFunctionComparisonModel extends AbstractFunctionComparisonModel {

	private Map<Function, Set<Function>> sourceToTargetsMap = new HashMap<>();

	/**
	 * Removes the given function from all comparisons in the model, whether
	 * stored as a source or target
	 * 
	 * @param function the function to remove
	 */
	@Override
	public void removeFunction(Function function) {
		if (doRemoveFunction(function)) {
			fixupActiveFunctions();
			fireModelDataChanged();
		}
	}

	/**
	 * Removes all the given functions from all comparisons in the model
	 * @param functions the functions to remove
	 */
	@Override
	public void removeFunctions(Collection<Function> functions) {
		boolean didRemove = false;
		for (Function function : functions) {
			didRemove |= doRemoveFunction(function);
		}
		if (didRemove) {
			fixupActiveFunctions();
			fireModelDataChanged();
		}
	}

	private boolean doRemoveFunction(Function function) {
		return removeFunctionFromTargets(function) || removeFunctionFromSources(function);
	}

	private void fixupActiveFunctions() {
		if (sourceToTargetsMap.isEmpty()) {
			activeFunctions = new Duo<>();
			return;
		}

		if (!containsFunction(LEFT, activeFunctions.get(LEFT))) {
			Function newLeft = getFunctions(LEFT).get(0);
			activeFunctions = activeFunctions.with(LEFT, newLeft);
		}
		if (!containsFunction(RIGHT, activeFunctions.get(RIGHT))) {
			Function newRight = getFunctions(RIGHT).get(0);
			activeFunctions = activeFunctions.with(RIGHT, newRight);
		}
	}

	private boolean removeFunctionFromTargets(Function function) {
		boolean didRemove = false;
		Iterator<Function> it = sourceToTargetsMap.keySet().iterator();

		while (it.hasNext()) {
			Function source = it.next();
			Set<Function> set = sourceToTargetsMap.get(source);
			didRemove |= set.remove(function);
			if (set.isEmpty()) {
				it.remove();
			}
		}
		return didRemove;
	}

	private boolean removeFunctionFromSources(Function function) {
		return sourceToTargetsMap.remove(function) != null;
	}

	/**
	 * Removes all functions in the model that come from the given
	 * program
	 * 
	 * @param program the program to remove functions from
	 */
	@Override
	public void removeFunctions(Program program) {
		Set<Function> functionsToRemove = findFunctions(program);
		removeFunctions(functionsToRemove);
	}

	private Set<Function> findFunctions(Program program) {
		Set<Function> functions = new HashSet<>();
		for (Entry<Function, Set<Function>> entry : sourceToTargetsMap.entrySet()) {
			Function source = entry.getKey();
			Set<Function> targets = entry.getValue();

			if (source.getProgram() == program) {
				functions.add(source);
			}
			for (Function function : targets) {
				if (function.getProgram() == program) {
					functions.add(function);
				}
			}
		}
		return functions;
	}

	@Override
	public List<Function> getFunctions(Side side) {
		if (side == LEFT) {
			return getSourceFunctions();
		}
		return getTargetFunctions();
	}

	@Override
	public boolean setActiveFunction(Side side, Function function) {
		// If the right side changes, nothing special happens so let the super handle it.
		// If the left side changes, the entire set of functions on the right will change, so
		// we need special handling for that case
		if (side == RIGHT) {
			return super.setActiveFunction(side, function);
		}

		if (function == activeFunctions.get(LEFT)) {
			return false;	// function is already selected
		}

		if (!containsFunction(side, function)) {
			return false;
		}

		activeFunctions = activeFunctions.with(side, function);
		Function newRightSideFunction = getFunctions(RIGHT).get(0);
		activeFunctions = activeFunctions.with(RIGHT, newRightSideFunction);

		fireModelDataChanged();
		return true;
	}

	private List<Function> getTargetFunctions() {
		List<Function> targets = new ArrayList<>();

		Function source = getActiveFunction(LEFT);
		if (source != null) {
			targets.addAll(sourceToTargetsMap.get(source));
		}
		Collections.sort(targets, FUNCTION_COMPARATOR);
		return targets;
	}

	public List<Function> getSourceFunctions() {
		List<Function> sourceFunctions = new ArrayList<>(sourceToTargetsMap.keySet());
		Collections.sort(sourceFunctions, FUNCTION_COMPARATOR);
		return sourceFunctions;
	}

	@Override
	public boolean isEmpty() {
		return sourceToTargetsMap.isEmpty();
	}

	/**
	 * Adds a new comparison to the model. If the sourceFunction already exists on the left side,
	 * then the target function will be added to that specific function's right side functions. 
	 * Otherwise, the source function will be added to the left side the given target as its only
	 * right side function.
	 * @param sourceFunction the left side function to add
	 * @param targetFunction the right side function to add for that source function
	 */
	public void addMatch(Function sourceFunction, Function targetFunction) {
		Set<Function> targets =
			sourceToTargetsMap.computeIfAbsent(sourceFunction, k -> new HashSet<>());
		targets.add(targetFunction);
		activeFunctions = new Duo<>(sourceFunction, targetFunction);
		fireModelDataChanged();
	}

	@Override
	protected boolean containsFunction(Side side, Function function) {
		if (side == LEFT) {
			return sourceToTargetsMap.containsKey(function);
		}
		return sourceToTargetsMap.get(activeFunctions.get(LEFT)).contains(function);
	}

}
