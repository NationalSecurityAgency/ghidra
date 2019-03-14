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
package docking.widgets.fieldpanel;

import java.awt.Component;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;

/**
 * An event related to component layout over a {@link FieldPanel}.
 * 
 * @see FieldPanelOverLayoutManager
 */
public class FieldPanelOverLayoutEvent {
	private final Field field;
	private final FieldLocation loc;
	private final Component component;

	private boolean consumed;
	private boolean cancelled;

	/**
	 * Create a new event on the given field, location, and component.
	 * @param field the field that will have a component placed over it
	 * @param loc the location of the field
	 * @param component the component to be placed over the field
	 */
	public FieldPanelOverLayoutEvent(Field field, FieldLocation loc, Component component) {
		this.field = field;
		this.loc = loc;
		this.component = component;
	}

	/**
	 * Get the field that will have a component placed over it
	 * @return the field
	 */
	public Field getField() {
		return field;
	}

	/**
	 * Get the field location
	 * @return the location of the field
	 */
	public FieldLocation getLocation() {
		return loc;
	}

	/**
	 * Get the component to be placed over the field
	 * @return the component
	 */
	public Component getComponent() {
		return component;
	}

	/**
	 * Prevent this event from being further processed.
	 * 
	 * The actual layout will still occur, though.
	 */
	public void consume() {
		consumed = true;
	}

	/**
	 * Check if this event has been consumed by an earlier listener.
	 * @return true if the event has been consumed, i.e., should not be further processed
	 */
	public boolean isConsumed() {
		return consumed;
	}

	/**
	 * Prevent the actual layout from taking place.
	 * 
	 * Further listeners may still process this event, though.
	 */
	public void cancel() {
		cancelled = true;
	}

	/**
	 * Check if the actual layout will be performed.
	 * @return true if the layout has been cancelled.
	 */
	public boolean isCancelled() {
		return cancelled;
	}
}
