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
package ghidra.feature.vt.gui.filters;

import java.lang.reflect.Constructor;
import java.util.HashSet;
import java.util.Set;

import javax.swing.Icon;
import javax.swing.JComponent;

import ghidra.framework.options.SaveState;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

/**
 * An interface to allow clients to provide a mechanism for filtering objects and to notify 
 * listeners when the state of the filter changes
 * 
 * @param <T> the type of item passed to the filter
 */
public abstract class Filter<T> {

	private Set<FilterStatusListener> listeners = new HashSet<FilterStatusListener>();

	/**
	 * Returns true if the given object passes this filter's criteria.  A value of false signals
	 * to exclude the object from the set of valid data.
	 * @param t the item to filter
	 * @return true if this item passes the filter and should be included in the results
	 */
	public abstract boolean passesFilter(T t);

	public abstract FilterEditingStatus getFilterStatus();

	public abstract void clearFilter();

	public abstract JComponent getComponent();

	public void dispose() {
		listeners.clear();
	}

	public void addFilterStatusListener(FilterStatusListener listener) {
		listeners.add(listener);
	}

	protected void fireStatusChanged(FilterEditingStatus status) {
		for (FilterStatusListener listener : listeners) {
			listener.filterStatusChanged(status);
		}
	}

	public abstract FilterShortcutState getFilterShortcutState();

	public abstract void readConfigState(SaveState saveState);

	public abstract void writeConfigState(SaveState saveState);

	public abstract boolean isSubFilterOf(Filter<T> otherFilter);

	public enum FilterEditingStatus {
		NONE("", null),
		DIRTY("Filter contents have changed, but are not yet applied", ResourceManager.loadImage(
			"images/bullet_black.png")),
		ERROR("Filter contents are not valid", ResourceManager.loadImage("images/no_small.png")),
		APPLIED("Filter applied", ResourceManager.loadImage("images/bullet_green.png"));

		private final String description;
		private final Icon icon;

		private FilterEditingStatus(String description, Icon icon) {
			this.description = description;
			this.icon = icon;
		}

		String getDescription() {
			return description;
		}

		Icon getIcon() {
			return icon;
		}
	}

	/**
	 * A state that describes ways for the filtering process to shortcut, or skip, full filtering.
	 */
	public enum FilterShortcutState {
		//@formatter:off
		/** Any item passed to a filter in this state will pass the filter */
		ALWAYS_PASSES, 
		
		/** Any item passed to a filter in this state must be checked to see if it passes the filter */
		REQUIRES_CHECK,
		
		/** Any item passed to a filter in this state will fail the filter */
		NEVER_PASSES
		//@formatter:on
	}

	/**
	 * Creates a copy of this filter.  This is useful for creating a disconnected snapshot of
	 * this filter.
	 * 
	 * @return the copy
	 */
	public Filter<T> createCopy() {
		Filter<T> copy = createEmptyCopy();
		SaveState ss = new SaveState();
		writeConfigState(ss);
		copy.readConfigState(ss);
		return copy;
	}

	/**
	 * Creates an empty copy of this filter object. 
	 * 
	 * <P>Note: for this code to work, each subclass must have a no-arg, public constructor.  
	 *          If not, then the differing subclass needs to override this method.
	 * 
	 * @return the new uninitialized instance
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected Filter<T> createEmptyCopy() {

		//
		// Note: for this code to work, each subclass must have a no-arg, public constructor.  
		//       If not, then the differing subclass needs to override this method.
		//

		Class<? extends Filter> clazz = getClass();
		try {
			Constructor<? extends Filter> constructor = clazz.getConstructor((Class<?>[]) null);
			Filter<?> newInstance = constructor.newInstance((Object[]) null);
			return (Filter<T>) newInstance;
		}
		catch (Exception e) {
			throw new AssertException("Exception copying filter '" + clazz.getSimpleName() +
				"'--missing empty constructor?", e);
		}
	}
}
