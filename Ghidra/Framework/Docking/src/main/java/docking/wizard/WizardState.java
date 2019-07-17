/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.util.*;
import java.util.Map.Entry;

public class WizardState<T> implements Cloneable {
	private Map<T, Object> map = new HashMap<T, Object>();
	private Map<T, Set<T>> dependentMap = new HashMap<T, Set<T>>();

    @Override
    protected Object clone() {
        WizardState<T> anakin = new WizardState<T>();
        anakin.map = new HashMap<T, Object>(map);
        Set<Entry<T,Set<T>>> entrySet = dependentMap.entrySet();
        for (Entry<T, Set<T>> entry : entrySet) {
            T key = entry.getKey();
            Set<T> value = entry.getValue();
            anakin.dependentMap.put(key, new HashSet<T>(value));
        }
        return anakin;
    }

	/**
	 * Gets the value for a property key.
	 * @param key the identifier for the property.  Typically, it would be a string or enum.
	 * @return the value associated with the given property key or null if the property has no
	 * value.
	 */
	public Object get(T key) {
		return map.get( key );
	}
	
	/**
	 * Sets the property value for a given property key.  Also clears out the property values for
	 * any properties that depend on this property.
	 * @param key the propertyKey whose value is to be set or changed with the new value.
	 * @param value the new value for the property.
	 */
	public void put(T key, Object value) {
	    if (map.containsKey(key)) {
	        Object oldValue = map.get(key);
	        if (oldValue == value) {
	            return;
	        }
	        if (oldValue != null && oldValue.equals(value)) {
	            return;
	        }
	    }
		map.put( key, value );
		clearDependents(key);
	}
	
	/**
	 * Removes the property key,value pair from this wizard state.
	 * @param key the property key of the property to be cleared.
	 */
	public void clear(T key) {
		Object removedValue = map.remove( key );
		if (removedValue != null) {
			clearDependents(key);
		}
	}

	/**
	 * Defines a dependency from one property to another.  A property dependency has the effect of
	 * clear the dependent's property value whenever the predecessor property is changed or cleared. 
	 * @param dependent the property whose value is to be cleared when the predecessor property is
	 * changed or cleared.
	 * @param predecessor the property that, when changed or cleared, will cause the dependent property
	 * to be cleared.
	 */
	public void addDependency(T dependent, T predecessor) {
		Set<T> dependents = dependentMap.get( predecessor );
		if (dependents == null) {
			dependents = new HashSet<T>();
			dependentMap.put( predecessor, dependents );
		}
		dependents.add(dependent);
	}

	private void clearDependents(T key) {
		Set<T> dependencies = dependentMap.get( key );
		if (dependencies != null) {
    		for ( T dependent : dependencies ) {
    			clear(dependent);
    		}
		}
	}

}
