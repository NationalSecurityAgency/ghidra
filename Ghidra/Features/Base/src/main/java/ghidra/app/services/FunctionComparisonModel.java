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
package ghidra.app.services;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.collections4.CollectionUtils;

import ghidra.app.plugin.core.functioncompare.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

/**
 * A collection of {@link FunctionComparison function comparison} 
 * objects that describe how functions may be compared. Each comparison object
 * is a mapping of a function (source) to a list of functions (targets). 
 * <p>
 * This model is intended to be used by the {@link FunctionComparisonProvider} 
 * as the basis for its display. It should never be created manually, and should
 * only be accessed via the {@link FunctionComparisonService}. 
 * <p>
 * Note: Subscribers may register to be informed of changes to this model via the
 * {@link FunctionComparisonModelListener comparison model listener} interface.
 */
public class FunctionComparisonModel {

	private List<FunctionComparison> comparisons = new ArrayList<>();
	private List<FunctionComparisonModelListener> listeners = new ArrayList<>();

	/**
	 * Adds the given subscriber to the list of those to be notified of model
	 * changes
	 * 
	 * @param listener the model change subscriber
	 */
	public void addFunctionComparisonModelListener(FunctionComparisonModelListener listener) {
		listeners.add(listener);
	}

	/**
	 * Returns a list of all comparisons in the model, in sorted order by 
	 * source function name
	 * 
	 * @return a list of all comparisons in the model
	 */
	public List<FunctionComparison> getComparisons() {
		List<FunctionComparison> toReturn = new ArrayList<>();
		toReturn.addAll(comparisons);
		Collections.sort(toReturn);
		return toReturn;
	}

	/**
	 * Replaces the current model with the comparisons provided
	 * 
	 * @param comparisons the new comparison model
	 */
	public void setComparisons(List<FunctionComparison> comparisons) {
		this.comparisons = comparisons;
	}

	/**
	 * Adds a single comparison to the model
	 * 
	 * @param comparison the comparison to add
	 */
	public void addComparison(FunctionComparison comparison) {
		comparisons.add(comparison);
	}

	/**
	 * Returns a list of all targets in the model (across all comparisons) for
	 * a given source function
	 * 
	 * @param source the source function
	 * @return list of associated target functions
	 */
	public Set<Function> getTargets(Function source) {
		Set<Function> targets = new HashSet<>();
		for (FunctionComparison fc : comparisons) {
			if (fc.getSource().equals(source)) {
				targets.addAll(fc.getTargets());
			}
		}

		return targets;
	}

	/**
	 * Updates the model with a set of functions to compare. This will add the
	 * functions to any existing {@link FunctionComparison comparisons} in the 
	 * model and create new comparisons for functions not represented.
	 * <p>
	 * Note: It is assumed that when using this method, all functions can be
	 * compared with all other functions; meaning each function will be added as 
	 * both a source AND a target. To specify a specific source/target
	 * relationship, use {@link #compareFunctions(Function, Function)}.
	 * 
	 * @param functions the set of functions to compare
	 */
	public void compareFunctions(Set<Function> functions) {
		if (CollectionUtils.isEmpty(functions)) {
			return; // not an error, just return
		}

		addToExistingComparisons(functions);
		createNewComparisons(functions);

		fireModelChanged();
	}

	/**
	 * Compares two functions. If a comparison already exists in the model for
	 * the given source, the target will simply be added to it; otherwise a
	 * new comparison will be created.
	 * 
	 * @param source the source function
	 * @param target the target function
	 */
	public void compareFunctions(Function source, Function target) {
		FunctionComparison fc = getOrCreateComparison(source);
		fc.addTarget(target);

		fireModelChanged();
	}

	/**
	 * Removes the given function from all comparisons in the model, whether
	 * stored as a source or target
	 * 
	 * @param function the function to remove
	 */
	public void removeFunction(Function function) {
		List<FunctionComparison> comparisonsToRemove = new ArrayList<>();

		Iterator<FunctionComparison> iter = comparisons.iterator();
		while (iter.hasNext()) {

			// First remove any comparisons that have the function as its source
			FunctionComparison fc = iter.next();
			if (fc.getSource().equals(function)) {
				comparisonsToRemove.add(fc);
				continue;
			}

			// Now remove the function from the target list (if it's there)
			fc.getTargets().remove(function);
		}

		comparisons.removeAll(comparisonsToRemove);

		fireModelChanged();
	}

	/**
	 * Removes all functions in the model that come from the given
	 * program
	 * 
	 * @param program the program to remove functions from
	 */
	public void removeFunctions(Program program) {
		Set<Function> sources = getSourceFunctions();
		Set<Function> targets = getTargetFunctions();

		Set<Function> sourcesToRemove = sources.stream()
				.filter(f -> f.getProgram().equals(program))
				.collect(Collectors.toSet());

		Set<Function> targetsToRemove = targets.stream()
				.filter(f -> f.getProgram().equals(program))
				.collect(Collectors.toSet());

		sourcesToRemove.stream().forEach(f -> removeFunction(f));
		targetsToRemove.stream().forEach(f -> removeFunction(f));
	}

	/**
	 * Returns all source functions in the model
	 * 
	 * @return a set of all source functions
	 */
	public Set<Function> getSourceFunctions() {
		Set<Function> items = new HashSet<>();
		for (FunctionComparison fc : comparisons) {
			items.add(fc.getSource());
		}
		return items;
	}

	/**
	 * Returns all target functions in the model
	 * 
	 * @return a set of all target functions
	 */
	public Set<Function> getTargetFunctions() {
		Set<Function> items = new HashSet<>();
		Iterator<FunctionComparison> iter = comparisons.iterator();
		while (iter.hasNext()) {
			FunctionComparison fc = iter.next();
			items.addAll(fc.getTargets());
		}

		return items;
	}

	/**
	 * Returns a set of all target functions for a given source
	 * 
	 * @param source the source function to search for
	 * @return the set of associated target functions
	 */
	public Set<Function> getTargetFunctions(Function source) {
		Set<Function> items = new HashSet<>();
		Iterator<FunctionComparison> iter = comparisons.iterator();
		while (iter.hasNext()) {
			FunctionComparison fc = iter.next();
			if (!fc.getSource().equals(source)) {
				continue;
			}
			items.addAll(fc.getTargets());
		}

		return items;
	}

	/**
	 * Creates a {@link FunctionComparison comparison} for each function
	 * given, such that each comparison will have every other function as its 
	 * targets. For example, given three functions, f1, f2, and f3, this is what the
	 * model will look like after this call:
	 * <li>comparison 1:</li>
	 *    <ul>
	 *    <li> source: f1</li>
	 *    <li> targets: f2, f3</li>
	 *    </ul>
	 * <li>comparison 2:</li>
	 *    <ul>
	 *    <li> source: f2</li>
	 *    <li> targets: f1, f3</li>
	 *    </ul>
	 * <li>comparison 3:</li>
	 *    <ul>
	 *    <li> source: f3</li>
	 *    <li> targets: f1, f2</li>
	 *    </ul>
	 *   
	 * If this model already contains a comparison for a given function 
	 * (meaning the model contains a comparison with the function as the 
	 * source) then that function is skipped. 
	 * <p>
	 * Note that this could be a long-running process if many (thousands) 
	 * functions are chosen to compare, hence the monitored task. In practice 
	 * this should never be the case, as users will likely not be
	 * comparing more than a handful of functions at any given time.
	 * 
	 * @param functions the set of functions to create comparisons for
	 */
	private void createNewComparisons(Set<Function> functions) {

		TaskLauncher.launchModal("Creating Comparisons", (monitor) -> {

			// Remove any functions that already have an comparison in the 
			// model; these will be ignored
			functions.removeIf(f -> comparisons.stream()
					.anyMatch(fc -> f.equals(fc.getSource())));

			monitor.setIndeterminate(false);
			monitor.setMessage("Creating new comparisons");
			monitor.initialize(functions.size());

			// Save off all the existing targets in the model; these have to be 
			// added to any new comparisons
			Set<Function> existingTargets = getTargetFunctions();

			// Now loop over the given functions and create new comparisons
			for (Function f : functions) {
				if (monitor.isCancelled()) {
					Msg.info(this, "Function comparison operation cancelled");
					return;
				}

				FunctionComparison fc = new FunctionComparison();
				fc.setSource(f);
				fc.addTargets(functions);
				fc.addTargets(existingTargets);
				comparisons.add(fc);
				monitor.incrementProgress(1);
			}
		});

	}

	/**
	 * Searches the model for a comparison that has the given function as its
	 * source; if not found, a new comparison is created
	 * 
	 * @param source the source function to search for
	 * @return a function comparison object for the given source
	 */
	private FunctionComparison getOrCreateComparison(Function source) {
		for (FunctionComparison fc : comparisons) {
			if (fc.getSource().equals(source)) {
				return fc;
			}
		}

		FunctionComparison fc = new FunctionComparison();
		fc.setSource(source);
		comparisons.add(fc);
		return fc;
	}

	/**
	 * Adds a given set of functions to every target list in every 
	 * comparison in the model
	 * 
	 * @param functions the functions to add
	 */
	private void addToExistingComparisons(Set<Function> functions) {
		for (FunctionComparison fc : comparisons) {
			fc.getTargets().addAll(functions);
		}
	}

	/**
	 * Sends model-change notifications to all subscribers. The updated model
	 * is sent in the callback.
	 */
	private void fireModelChanged() {
		listeners.forEach(l -> l.modelChanged(comparisons));
	}
}
