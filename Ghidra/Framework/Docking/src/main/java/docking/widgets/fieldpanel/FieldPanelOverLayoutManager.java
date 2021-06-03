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
import java.awt.Container;
import java.awt.Dimension;
import java.awt.LayoutManager;
import java.awt.LayoutManager2;
import java.awt.Rectangle;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.LayoutListener;
import docking.widgets.fieldpanel.support.AnchoredLayout;
import docking.widgets.fieldpanel.support.FieldLocation;

/**
 * A {@link LayoutManager} that can be applied to a {@link FieldPanel}, allowing
 * {@link Component}s to be placed over a given field location.
 * 
 * To apply it, use {@link Container#setLayout(LayoutManager)} to install it. In this case, the
 * {@link Container} must be a {@link FieldPanel}. Then, use
 * {@link Container#add(Component, Object)}, passing a {@link FieldLocation} as the constraint.
 * Currently, you must call {@link #layoutContainer(Container)} manually after you add or remove
 * any components.
 * 
 * When this layout manager is removed from the {@link FieldPanel}, you should call
 * {@link #unregister()} in order to dispose of internal resources.
 */
public class FieldPanelOverLayoutManager implements LayoutManager2 {
	private final Map<FieldLocation, Component> componentsByLocation = new HashMap<>();
	private final Map<Component, FieldLocation> locationsByComponent = new HashMap<>();
	private final FieldPanel fieldpane;
	private final MyListener listener = new MyListener();

	private final List<FieldPanelOverLayoutListener> layoutListeners = new ArrayList<>();

	public FieldPanelOverLayoutManager(FieldPanel fieldpane) {
		this.fieldpane = fieldpane;

		fieldpane.addLayoutListener(listener);
	}

	/**
	 * A listener for callbacks on the {@link FieldPanel}'s field layout changing.
	 */
	private class MyListener implements LayoutListener {
		@Override
		public void layoutsChanged(List<AnchoredLayout> layouts) {
			Set<Component> invisible = new HashSet<>(componentsByLocation.values());
			for (AnchoredLayout layout : layouts) {
				// Protect against indexing an empty array. Besides, if no fields, no components.
				if (layout.getNumFields() == 0) {
					continue;
				}
				BigInteger index = layout.getIndex();
				// Now, look over the fields and map the components.
				for (int i = 0; i < layout.getNumFields(); i++) {
					FieldLocation loc = new FieldLocation(index, i);
					Field field = layout.getField(i);
					Component comp = componentsByLocation.get(loc);
					if (comp != null) {
						Rectangle r = layout.getFieldBounds(i);
						comp.setBounds(r);

						FieldPanelOverLayoutEvent ev =
							new FieldPanelOverLayoutEvent(field, loc, comp);
						fireLayoutListeners(ev);
						if (ev.isCancelled()) {
							continue;
						}
						comp.setVisible(true);
						invisible.remove(comp);
					}
				}
			}
			for (Component comp : invisible) {
				comp.setVisible(false);
			}
		}
	}

	/**
	 * Remove my callbacks from the {@link FieldPanel}
	 */
	public void unregister() {
		fieldpane.removeLayoutListener(listener);
	}

	/**
	 * Add a component to be position over the given location
	 * @param loc the location of the field to occlude
	 * @param comp the component to be placed over the field
	 */
	protected void addComponent(FieldLocation loc, Component comp) {
		loc = new FieldLocation(loc.getIndex(), loc.getFieldNum());

		componentsByLocation.put(loc, comp);
		locationsByComponent.put(comp, loc);
	}

	/**
	 * Remove a component by its field location
	 * @param loc the location of the field
	 * @return true if there was a component placed at the given location
	 */
	protected boolean removeComponent(FieldLocation loc) {
		Component comp = componentsByLocation.remove(loc);
		if (comp == null) {
			return false;
		}
		locationsByComponent.remove(comp);
		return true;
	}

	/**
	 * Remove a component
	 * @param comp the component to remove
	 * @return true if the component existed
	 */
	protected boolean removeComponent(Component comp) {
		FieldLocation loc = locationsByComponent.remove(comp);
		if (loc == null) {
			return false;
		}
		componentsByLocation.remove(loc);
		return true;
	}

	/**
	 * Tickle the layout manager, so we get a callback to map the components onto the layout.
	 */
	protected void trickMapComponents() {
		fieldpane.scrollView(0); // This will cause layoutsChanged to be called.
	}

	/**
	 * Add a listener for overlay layout events
	 * @param listener the listener to add
	 */
	public void addLayoutListener(FieldPanelOverLayoutListener listener) {
		layoutListeners.add(listener);
	}

	/**
	 * Remove a listener for overlay layout events
	 * @param listener the listener to remove
	 */
	public void removeLayoutListener(FieldPanelOverLayoutListener listener) {
		layoutListeners.remove(listener);
	}

	/**
	 * Get the list of register overlay layout event listeners
	 * @return the array
	 */
	public FieldPanelOverLayoutListener[] getLayoutListeners() {
		return layoutListeners.toArray(new FieldPanelOverLayoutListener[0]);
	}

	@SuppressWarnings("unchecked")
	public <T> T[] getListeners(Class<T> listenerType) {
		if (listenerType == FieldPanelOverLayoutListener.class) {
			return (T[]) getLayoutListeners();
		}
		return null;
	}

	/**
	 * Fire the given overlay layout event to all registered listeners
	 * @param ev
	 */
	protected void fireLayoutListeners(FieldPanelOverLayoutEvent ev) {
		for (FieldPanelOverLayoutListener l : layoutListeners) {
			if (ev.isConsumed()) {
				return;
			}
			l.fieldLayout(ev);
		}
	}

	/* ********************************************************************************************
	 * LayoutManager
	 */

	@Override
	public void addLayoutComponent(String name, Component comp) {
		addComponent(new FieldLocation(0, 0), comp);
	}

	@Override
	public void addLayoutComponent(Component comp, Object constraints) {
		addComponent((FieldLocation) constraints, comp);
	}

	@Override
	public void removeLayoutComponent(Component comp) {
		removeComponent(comp);
	}

	@Override
	public Dimension preferredLayoutSize(Container parent) {
		return null;
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		return null;
	}

	@Override
	public Dimension maximumLayoutSize(Container target) {
		return null;
	}

	@Override
	public void layoutContainer(Container parent) {
		if (!parent.equals(fieldpane)) {
			throw new IllegalArgumentException("" + parent);
		}
		trickMapComponents();
	}

	@Override
	public float getLayoutAlignmentX(Container target) {
		return 0.5f;
	}

	@Override
	public float getLayoutAlignmentY(Container target) {
		return 0.5f;
	}

	@Override
	public void invalidateLayout(Container target) {
		trickMapComponents();
		fieldpane.repaint();
	}
}
