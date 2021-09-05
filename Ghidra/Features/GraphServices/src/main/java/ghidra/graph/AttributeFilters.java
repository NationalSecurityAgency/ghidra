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
package ghidra.graph;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.*;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.swing.AbstractButton;
import javax.swing.JRadioButton;
import javax.swing.event.EventListenerList;

import com.google.common.collect.HashMultiset;
import com.google.common.collect.Multiset;

import ghidra.service.graph.Attributed;

/**
 * A filtering mechanism where filters (and filter control buttons) are discovered and created
 * based on the contents of the Attribute map
 */
public class AttributeFilters implements ItemSelectable {

	public static class Builder {
		/**
		 * key names that are precluded from being considered for filter creation
		 */
		private Collection<String> excludedAttributes = Collections.emptyList();
		/**
		 * all of the Attributed elements that will be considered for the creation of filters
		 */
		private Set<? extends Attributed> elements;
		/**
		 * a factor used to control whether a filter is created or not.
		 *     {@code double threshold = Math.max(2, elements.size() * maxFactor);}
		 *     determines the threshold for the creation of a filter on an attribute value
		 */
		private double maxFactor;
		/**
		 * provides a toolkit button control for the filters ({@link JRadioButton} by default)
		 */
		private Supplier<AbstractButton> buttonSupplier = JRadioButton::new;
		/**
		 * a {@link Function} to allow custom coloring of the individual toolkit button foreground
		 */
		private Function<String, Paint> paintFunction = v -> Color.black;


		/**
		 * @param excluded ignored keys
		 * @return the Builder
		 */
		public Builder exclude(Collection<String> excluded) {
			this.excludedAttributes = excluded;
			return this;
		}

		/**
		 * @param newElements the elements to consider
		 * @return this Builder
		 */
		public Builder elements(Set<? extends Attributed> newElements) {
			this.elements = newElements;
			return this;
		}

		/**
		 * @param newMaxFactor the factor to use in creating a threshold for filter creation
		 * @return this Builder
		 */
		public Builder maxFactor(double newMaxFactor) {
			this.maxFactor = newMaxFactor;
			return this;
		}

		/**
		 * @param newButtonSupplier the toolkit button to provide
		 * @return this Builder
		 */
		public Builder buttonSupplier(Supplier<AbstractButton> newButtonSupplier) {
			this.buttonSupplier = newButtonSupplier;
			return this;
		}

		/**
		 * @param newPaintFunction the {@code Function} to color the toolkit buttons
		 * @return this Builder
		 */
		public Builder paintFunction(Function<String, Paint> newPaintFunction) {
			this.paintFunction = newPaintFunction;
			return this;
		}

		/**
		 * create the configured instance
		 * @return the configured instance
		 */
		public AttributeFilters build() {
			return new AttributeFilters(this);
		}
	}

	/**
	 *
	 * @return a builder to configure an instance of AttributeFilters
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 *
	 * @param builder configurations for the instance
	 */
	private AttributeFilters(Builder builder) {
		this(builder.excludedAttributes, builder.elements, builder.maxFactor,
			builder.buttonSupplier, builder.paintFunction);
	}

	List<AbstractButton> buttons = new ArrayList<>();
	Multiset<String> multiset = HashMultiset.create();

	Set<String> selectedTexts = new HashSet<>();

	protected EventListenerList listenerList = new EventListenerList();

	/**
	 *
	 * @param precludedNames keys that will not be considered for filters
	 * @param elements elements that will be considered for filters
	 * @param maxFactor controls the threshold for filter creation
	 * @param buttonSupplier provides toolkit controls for the filters
	 * @param paintFunction provides a way to individually color the control buttons
	 */
	private AttributeFilters(Collection<String> precludedNames, Set<? extends Attributed> elements,
			double maxFactor,
			Supplier<AbstractButton> buttonSupplier, Function<String, Paint> paintFunction) {

		// count up the unique attribute values (skipping the 'precluded names' we know we don't want)
		for (Attributed element : elements) {
			Map<String, String> attributeMap = new HashMap<>(element.getAttributes());
			for (Map.Entry<String, String> entry : attributeMap.entrySet()) {
				if (!precludedNames.contains(entry.getKey())) {
					multiset.add(entry.getValue());
				}
			}
		}

		if (maxFactor == 0) {
			maxFactor = .01;
		}
		double threshold = Math.max(2, elements.size() * maxFactor);
		// accept the values with cardinality above the max of 2 and maxFactor times the of the number elements.
		multiset.removeIf(s -> multiset.count(s) < threshold);
		// create a button for every element that was retained
		multiset.elementSet();
		for (String key : multiset.elementSet()) {
			AbstractButton button = buttonSupplier.get();
			button.setForeground((Color) paintFunction.apply(key));
			button.setText(key);
			button.addItemListener(item -> {
				if (item.getStateChange() == ItemEvent.SELECTED) {
					selectedTexts.add(button.getText());
					fireItemStateChanged(new ItemEvent(this, ItemEvent.ITEM_STATE_CHANGED,
						this.selectedTexts, ItemEvent.SELECTED));

				}
				else if (item.getStateChange() == ItemEvent.DESELECTED) {
					selectedTexts.remove(button.getText());
					fireItemStateChanged(new ItemEvent(this, ItemEvent.ITEM_STATE_CHANGED,
						this.selectedTexts, ItemEvent.DESELECTED));
				}
			});
			buttons.add(button);
		}
	}

	/**
	 *
	 * @return the filter control toolkit buttons
	 */
	public List<AbstractButton> getButtons() {
		return buttons;
	}

	// event support:
	@Override
	public Object[] getSelectedObjects() {
		return selectedTexts.toArray();
	}

	/**
	 * add a listener to react to changes in the filter selection
	 * @param l the listener
	 */
	@Override
	public void addItemListener(ItemListener l) {
		listenerList.add(ItemListener.class, l);
	}

	/**
	 * remove a listener for filter changes
	 * @param l the listener
	 */
	@Override
	public void removeItemListener(ItemListener l) {
		listenerList.remove(ItemListener.class, l);
	}

	/**
	 * alert listeners that there is a change in the selected filters
	 * @param e the event
	 */
	protected void fireItemStateChanged(ItemEvent e) {
		// Guaranteed to return a non-null array
		Object[] listeners = listenerList.getListenerList();
		// Process the listeners last to first, notifying
		// those that are interested in this event
		for (int i = listeners.length - 2; i >= 0; i -= 2) {
			if (listeners[i] == ItemListener.class) {
				((ItemListener) listeners[i + 1]).itemStateChanged(e);
			}
		}
	}
}
