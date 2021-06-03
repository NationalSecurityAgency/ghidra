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
package docking.wizard;

import ghidra.util.SystemUtilities;

import java.util.*;

public class WizardStateDependencyValidator<T> {
	
	private Set<T> dependentSet = new HashSet<T>();
	private Map<T, Set<T>> dependentMap = new HashMap<T, Set<T>>();
	private Map<T, Object> valueMap = new HashMap<T, Object>();
	
	/**
	 * Registers a dependency from one property state to another.  If the predecessor is null, then
	 * the dependent is registered such that a call to {@link #findAffectedDependants(WizardState)}
	 * will include that property key only if its cached value is null.  (i.e. the first time it 
	 * is called.)
	 * @param dependent the property key that depends on a previous property being set.
	 * @param predecessor the property key of the property that affects the dependent property.
	 */
	public void addDependency(T dependent, T predecessor) {
		dependentSet.add(dependent);
		if (predecessor != null) {
			Set<T> dependents = dependentMap.get( predecessor );
			if (dependents == null) {
				dependents = new HashSet<T>();
				dependentMap.put( predecessor, dependents );
			}
			dependents.add(dependent);
		}
	}
	
	/**
	 * Returns a set of all property keys that need to have their values set because a predecessor 
	 * property has been changed that may affect the valid values for this property.  Also, any
	 * property keys that don't have a value in the local cache will be returned.
	 * @param globalState the global WizardState that is passed from one wizard panel to the next.
	 * @return the set of property keys whose values should be (re)computed.
	 */
	public Set<T> findAffectedDependants(WizardState<T> globalState) {
		Set<T> affectedDependendants = new HashSet<T>();
		
		for ( T predecessor : dependentMap.keySet() ) {
			Object globalValue = globalState.get( predecessor );
			Object localValue = valueMap.get( predecessor );
			if (!SystemUtilities.isEqual( globalValue, localValue )) {
				affectedDependendants.addAll( dependentMap.get( predecessor ) );
			}
		}
		for (T dependant : dependentSet) {
			if (valueMap.get( dependant ) == null) {
				affectedDependendants.add( dependant );
			}
		}
		
		return affectedDependendants;
	}
	
	/**
	 * Updates the local cache values for all the relevant properties.  This method should be
	 * called from a wizard panel when the "next" action is invoked (i.e. the user values have been
	 * accepted).
	 * @param globalState The WizardState containing all the property values.
	 */
	public void updatePropertyValues(WizardState<T> globalState) {
		for ( T dependent : dependentSet ) {
			valueMap.put( dependent, globalState.get( dependent ) );
		}
		for ( T trigger : dependentMap.keySet()) {
			valueMap.put( trigger, globalState.get( trigger ));
		}
	}
}
