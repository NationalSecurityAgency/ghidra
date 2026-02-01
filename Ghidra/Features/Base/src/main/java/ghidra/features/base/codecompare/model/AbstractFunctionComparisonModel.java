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

import java.util.*;

import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/**
 * Base class for implementers of the FunctionComparisonModel. Provides listener support and
 * tracking for the selected function for each side.
 */
public abstract class AbstractFunctionComparisonModel implements FunctionComparisonModel {
	public static Comparator<Function> FUNCTION_COMPARATOR = new FunctionComparator();
	private List<FunctionComparisonModelListener> listeners = new ArrayList<>();
	protected Duo<Function> activeFunctions = new Duo<>();

	@Override
	public void addFunctionComparisonModelListener(FunctionComparisonModelListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeFunctionComparisonModelListener(FunctionComparisonModelListener listener) {
		listeners.remove(listener);
	}

	@Override
	public boolean setActiveFunction(Side side, Function function) {
		if (activeFunctions.get(side) == function) {
			return false;
		}
		if (!containsFunction(side, function)) {
			return false;
		}
		activeFunctions = activeFunctions.with(side, function);
		fireActiveFunctionChanged(side, function);
		return true;
	}

	@Override
	public Function getActiveFunction(Side side) {
		return activeFunctions.get(side);
	}

	private void fireActiveFunctionChanged(Side side, Function function) {
		listeners.forEach(l -> l.activeFunctionChanged(side, function));
	}

	protected void fireModelDataChanged() {
		listeners.forEach(l -> l.modelDataChanged());
	}

	protected abstract boolean containsFunction(Side side, Function function);

	/**
	 * Orders functions by program path and then name and then address
	 */
	private static class FunctionComparator implements Comparator<Function> {

		@Override
		public int compare(Function o1, Function o2) {
			String o1Path = o1.getProgram().getDomainFile().getPathname();
			String o2Path = o2.getProgram().getDomainFile().getPathname();

			String o1Name = o1.getName();
			String o2Name = o2.getName();

			if (o1Path.equals(o2Path)) {
				if (o1Name.equals(o2Name)) {
					return o1.getEntryPoint().compareTo(o2.getEntryPoint());
				}
				return o1Name.compareTo(o2Name);
			}

			return o1Path.compareTo(o2Path);
		}
	}
}
