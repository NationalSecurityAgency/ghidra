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
package ghidra.features.base.codecompare.model;

import static ghidra.util.datastruct.Duo.Side.*;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/** 
 * Basic FunctionComparisonModel where a set of functions can be compared with each other
 */
public class AnyToAnyFunctionComparisonModel extends AbstractFunctionComparisonModel {
	private Set<Function> functions = new HashSet<>();

	public AnyToAnyFunctionComparisonModel(Collection<Function> functions) {
		this.functions.addAll(functions);
		List<Function> orderedFunctions = getOrderedFunctions();
		if (orderedFunctions.size() == 1) {
			setActiveFunction(LEFT, orderedFunctions.get(0));
			setActiveFunction(RIGHT, orderedFunctions.get(0));
		}
		else if (orderedFunctions.size() > 1) {
			setActiveFunction(LEFT, orderedFunctions.get(0));
			setActiveFunction(RIGHT, orderedFunctions.get(1));
		}
	}

	public AnyToAnyFunctionComparisonModel(Function... functions) {
		this(Arrays.asList(functions));
	}

	@Override
	public List<Function> getFunctions(Side side) {
		return getOrderedFunctions();
	}

	@Override
	public void removeFunction(Function function) {
		removeFunctions(Set.of(function));
	}

	@Override
	public void removeFunctions(Collection<Function> functionsToRemove) {
		int beforeSize = functions.size();
		functions.removeAll(functionsToRemove);
		int afterSize = functions.size();
		if (beforeSize != afterSize) {
			fixupActiveFunctions();
			fireModelDataChanged();
		}
	}

	@Override
	public void removeFunctions(Program program) {
		Set<Function> functionsToRemove = functions.stream()
				.filter(f -> f.getProgram().equals(program))
				.collect(Collectors.toSet());

		removeFunctions(functionsToRemove);
	}

	@Override
	public boolean isEmpty() {
		return functions.isEmpty();
	}

	public void addFunctions(Collection<Function> additionalFunctions) {
		if (additionalFunctions.isEmpty()) {
			return;
		}
		functions.addAll(additionalFunctions);
		fireModelDataChanged();
		setActiveFunction(RIGHT, additionalFunctions.iterator().next());
	}

	public void addFunction(Function function) {
		addFunctions(List.of(function));
	}

	@Override
	protected boolean containsFunction(Side side, Function function) {
		return functions.contains(function);
	}

	private List<Function> getOrderedFunctions() {
		List<Function> functionsList = new ArrayList<>(functions);
		Collections.sort(functionsList, FUNCTION_COMPARATOR);
		return functionsList;
	}

	private void fixupActiveFunctions() {
		Function left = getActiveFunction(LEFT);
		Function right = getActiveFunction(RIGHT);
		boolean containsLeft = functions.contains(left);
		boolean containsRight = functions.contains(right);
		if (containsLeft && containsRight) {
			return;
		}

		Function firstFunction = functions.isEmpty() ? null : getOrderedFunctions().get(0);

		if (!containsLeft) {
			left = firstFunction;
		}
		if (!containsRight) {
			right = firstFunction;
		}

		activeFunctions = new Duo<>(left, right);
	}

}
