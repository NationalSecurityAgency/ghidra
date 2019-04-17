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
package ghidra.program.util;

import generic.stl.Pair;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class VariableStorageConflicts {

	private List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
		new ArrayList<Pair<List<Variable>, List<Variable>>>();
	private boolean ignoreParamToParamConflicts;
	private List<Variable> nonOverlappingVariables1 = new ArrayList<Variable>();
	private List<Variable> nonOverlappingVariables2 = new ArrayList<Variable>();

	private boolean paramOnlyAddressSets;

	private boolean parametersConflicted = false;

	/**
	 * Construct a VariableStorageConflicts object for the variables contained within two
	 * functions.
	 * @param variablesList1
	 * @param variablesList2
	 * @param ignoreParamToParamConflicts if true param-to-param overlaps will be ignored unless
	 * a param-to-local overlap occurs in which case all params will be pulled in to the
	 * overlap.  If true, it is assumed that the current overlap iteration was initiated by
	 * a parameter overlap check.
	 * @param monitor
	 * @throws CancelledException
	 */
	public VariableStorageConflicts(List<Variable> variablesList1, List<Variable> variablesList2,
			boolean ignoreParamToParamConflicts, TaskMonitor monitor) throws CancelledException {

		// create copies of variable lists
		List<Variable> variables1 = new ArrayList<>(variablesList1);
		List<Variable> variables2 = new ArrayList<>(variablesList2);

		this.ignoreParamToParamConflicts = ignoreParamToParamConflicts;

		List<Variable> overlapList1 = null;
		List<Variable> overlapList2 = null;
		AddressSet set1 = null;
		AddressSet set2 = null;

		for (int i = 0; i < variables1.size(); i++) {
			monitor.checkCanceled();
			Variable var1 = variables1.get(i);
			if (var1 == null) {
				continue; // already consumed
			}
			variables1.set(i, null);
			Variable var2 =
				(var1 instanceof Parameter) ? removeMatchingParameter((Parameter) var1, variables2)
						: removeMatchingVariable(var1, variables2);
			if (var2 != null) {
				nonOverlappingVariables1.add(var1);
				nonOverlappingVariables2.add(var2);
				continue; // matched variables never conflict
			}
			if (overlapList1 == null) {
				overlapList1 = new ArrayList<Variable>();
				overlapList2 = new ArrayList<Variable>();
				set1 = new AddressSet();
				set2 = new AddressSet();
			}
			else {
				set1.clear(); // previous attempt had no overlap
			}
			addToAddressSet(set1, var1.getVariableStorage());
			paramOnlyAddressSets = (var1 instanceof Parameter);
			getOverlappingVariables(var1.getFirstUseOffset(), variables1, set1, overlapList1,
				variables2, set2, overlapList2, monitor);
			if (overlapList2.isEmpty()) {
				nonOverlappingVariables1.add(var1);
			}
			else {
				overlapList1.add(var1);

				if (var1 instanceof Parameter) {
					parametersConflicted = true;
					if (addAllParameters(variables1, overlapList1, set1, nonOverlappingVariables1)) {
						// re-check if more parameters added
						getOverlappingVariables(var1.getFirstUseOffset(), variables1, set1,
							overlapList1, variables2, set2, overlapList2, monitor);
					}
				}

				Pair<List<Variable>, List<Variable>> pair =
					new Pair<List<Variable>, List<Variable>>(overlapList1, overlapList2);
				overlappingVariables.add(pair);
				overlapList1 = null;
				overlapList2 = null;
				set1 = null;
				set2 = null;
			}
		}
	}

	/**
	 * Recursively expand the variable storage (set1,set2) to encompass all
	 * variables associated with the corresponding sets (variables1,variables2) which
	 * intersects the other set.  Any variables added to the overlap set will also be added
	 * to the corresponding overlapList.
	 * @param firstUseOffset first use offset or -1 for parameter
	 * @param variables1
	 * @param set1
	 * @param overlapList1
	 * @param variables2
	 * @param set2
	 * @param overlapList2
	 * @param monitor
	 * @throws CancelledException
	 */
	private void getOverlappingVariables(int firstUseOffset, List<Variable> variables1,
			AddressSet set1, List<Variable> overlapList1, List<Variable> variables2,
			AddressSet set2, List<Variable> overlapList2, TaskMonitor monitor)
			throws CancelledException {
		boolean expanded = true;
		while (expanded) {
			expanded = false;
			for (int i = 0; !set1.isEmpty() && i < variables2.size(); i++) {
				expanded |=
					findOverlaps(firstUseOffset, variables2, i, overlapList2, set2,
						nonOverlappingVariables2, set1);
			}
			for (int i = 0; !set2.isEmpty() && i < variables1.size(); i++) {
				monitor.checkCanceled();
				expanded |=
					findOverlaps(firstUseOffset, variables1, i, overlapList1, set1,
						nonOverlappingVariables1, set2);
			}
		}
	}

	private boolean findOverlaps(int firstUseOffset, List<Variable> variables, int index,
			List<Variable> overlapList, AddressSet overlapSet, List<Variable> nonOverlapList,
			AddressSetView intersectSet) {

		Variable var = variables.get(index);
		if (var == null) {
			return false; // already consumed
		}
		if (var.getFirstUseOffset() != firstUseOffset) {
			return false;
		}
		if (paramOnlyAddressSets && ignoreParamToParamConflicts && (var instanceof Parameter)) {
			return false;
		}

		boolean expanded = false;
		VariableStorage storage = var.getVariableStorage();
		if (storage.intersects(intersectSet)) {

			expanded |= true;
			paramOnlyAddressSets = false;

			variables.set(index, null); // avoid concurrent modification and mark as consumed
			addToAddressSet(overlapSet, storage);
			overlapList.add(var);

			// if parameter, include all parameters in same overlap list
			if (var instanceof Parameter) {
				parametersConflicted = true;
				addAllParameters(variables, overlapList, overlapSet, nonOverlapList);
			}
		}
		return expanded;
	}

	private static boolean addAllParameters(List<Variable> variables, List<Variable> overlapList,
			AddressSet overlapSet, List<Variable> nonOverlapList) {
		boolean parametersAdded = false;
		for (int i = 0; i < variables.size(); i++) {
			Variable v = variables.get(i);
			if (!(v instanceof Parameter)) {
				continue;
			}
			variables.set(i, null); // avoid concurrent modification and mark as consumed
			addToAddressSet(overlapSet, v.getVariableStorage());
			overlapList.add(v);
			parametersAdded = true;
		}

		Iterator<Variable> iter = nonOverlapList.iterator();
		while (iter.hasNext()) {
			Variable v = iter.next();
			if (!(v instanceof Parameter)) {
				continue;
			}
			iter.remove();
			addToAddressSet(overlapSet, v.getVariableStorage());
			overlapList.add(v);
			parametersAdded = true;
		}
		return parametersAdded;
	}

	private static void addToAddressSet(AddressSet set, VariableStorage storage) {
		List<Register> registers = storage.getRegisters();
		if (registers != null) {
			for (Register reg : registers) {
				Address minAddr = reg.getAddress();
				Address maxAddr = minAddr.add(reg.getMinimumByteSize() - 1);
				set.addRange(minAddr, maxAddr);
			}
		}
		for (Varnode varnode : storage.getVarnodes()) {
			Address minAddr = varnode.getAddress();
			Address maxAddr = minAddr.add(varnode.getSize() - 1);
			set.addRange(minAddr, maxAddr);
		}
	}

	public List<Pair<List<Variable>, List<Variable>>> getOverlappingVariables() {
		return overlappingVariables;
	}

	public boolean hasOverlapConflict() {
		return !overlappingVariables.isEmpty();
	}

	public boolean hasParameterConflict() {
		return parametersConflicted;
	}

	/**
	 * Check to see if either var1 or var2 is contained within the conflicted/overlapping
	 * set of variables.  In general, one of the specified variables should be null.
	 * @param var1 a variable which corresponds to function1 at time of construction or null
	 * @param var2 a variable which corresponds to function2 at time of construction or null
	 * @return true if either variable is contained within the conflicted/overlapping
	 * set of variables. 
	 */
	public boolean isConflicted(Variable var1, Variable var2) {
		for (Pair<List<Variable>, List<Variable>> pair : overlappingVariables) {
			if (var1 != null && containsVariable(pair.first, var1)) {
				return true;
			}
			if (var2 != null && containsVariable(pair.second, var2)) {
				return true;
			}
		}
		return false;
	}

	private boolean containsVariable(List<Variable> list, Variable var) {
		for (Variable v : list) {
			if (var.equals(v)) {
				return true;
			}
		}
		return false;
	}

	private Parameter removeMatchingParameter(Parameter var, List<Variable> list) {
		int ordinal = var.getOrdinal();
		VariableStorage storage = var.getVariableStorage();
		Iterator<Variable> iter = list.iterator();
		while (iter.hasNext()) {
			Variable v = iter.next();
			if (!(v instanceof Parameter)) {
				continue;
			}
			if (ordinal != ((Parameter) v).getOrdinal()) {
				continue;
			}
			if (!storage.equals(v.getVariableStorage())) {
				continue;
			}
			iter.remove();
			return (Parameter) v;
		}
		return null;
	}

	private Variable removeMatchingVariable(Variable var, List<Variable> list) {
		int firstUse = var.getFirstUseOffset();
		VariableStorage storage = var.getVariableStorage();
		Iterator<Variable> iter = list.iterator();
		while (iter.hasNext()) {
			Variable v = iter.next();
			if (v == null || (v instanceof Parameter)) {
				continue;
			}
			if (firstUse != v.getFirstUseOffset()) {
				continue;
			}
			if (!storage.equals(v.getVariableStorage())) {
				continue;
			}
			iter.remove();
			return v;
		}
		return null;

	}
}
