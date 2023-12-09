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
package docking.widgets.pathmanager;

import java.awt.*;
import java.beans.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public abstract class AbstractTypedPropertyEditor<T> implements PropertyEditor {
	private final List<PropertyChangeListener> listeners = new ArrayList<>();

	private T value = getInitialValue();

	protected T getInitialValue() {
		return null;
	}

	@SuppressWarnings("unchecked")
	protected T cast(Object value) {
		return (T) value;
	}

	@Override
	public void setValue(Object value) {
		T newValue = cast(value);
		if (Objects.equals(newValue, this.value)) {
			return;
		}
		T oldValue;
		List<PropertyChangeListener> listeners;
		synchronized (this.listeners) {
			oldValue = this.value;
			this.value = newValue;
			if (this.listeners.isEmpty()) {
				return;
			}
			listeners = List.copyOf(this.listeners);
		}
		PropertyChangeEvent evt = new PropertyChangeEvent(this, null, oldValue, newValue);
		for (PropertyChangeListener l : listeners) {
			l.propertyChange(evt);
		}
	}

	@Override
	public T getValue() {
		return value;
	}

	@Override
	public boolean isPaintable() {
		return false;
	}

	@Override
	public void paintValue(Graphics gfx, Rectangle box) {
		// Not paintable
	}

	@Override
	public String getJavaInitializationString() {
		return "???";
	}

	protected String toText(T value) {
		return Objects.toString(value);
	}

	@Override
	public String getAsText() {
		return toText(value);
	}

	protected abstract T fromText(String text);

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		setValue(fromText(text));
	}

	@Override
	public String[] getTags() {
		return null;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public void addPropertyChangeListener(PropertyChangeListener listener) {
		synchronized (listeners) {
			listeners.add(listener);
		}
	}

	@Override
	public void removePropertyChangeListener(PropertyChangeListener listener) {
		synchronized (listeners) {
			listeners.add(listener);
		}
	}
}
