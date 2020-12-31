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
package docking;

import java.util.*;
import java.util.Map.Entry;

/**
 * A class that tracks:
 * <ul>
 *  	<li>placeholders that are being used for a given provider
 *  	<li>placeholders that are no longer being used, which are available for reuse 
 * </ul>
 */
class PlaceholderSet {
	private Map<ComponentProvider, ComponentPlaceholder> activePlaceholderMap =
		new HashMap<>();
	private Set<ComponentPlaceholder> unusedPlaceholders = new HashSet<>();
	private PlaceholderManager manager;

	PlaceholderSet(PlaceholderManager manager) {
		this.manager = manager;
	}

	void addRestoredPlaceholder(ComponentPlaceholder restoredPlaceholder) {
		unusedPlaceholders.add(restoredPlaceholder);
	}

	void placeholderUsed(ComponentProvider provider, ComponentPlaceholder placeholder) {
		unusedPlaceholders.remove(placeholder);
		activePlaceholderMap.put(provider, placeholder);
	}

	ComponentPlaceholder placeholderFreed(ComponentProvider provider) {
		ComponentPlaceholder removedPlaceholder = activePlaceholderMap.remove(provider);
		if (removedPlaceholder == null) {
			// don't think this can happen
			return null;
		}

		boolean keepAround = !containsAnyMatchingPlaceholder(removedPlaceholder);
		if (keepAround) {
			unusedPlaceholders.add(removedPlaceholder);
		}

		manager.disposePlaceholder(removedPlaceholder, keepAround);

		return removedPlaceholder;
	}

	Set<ComponentPlaceholder> getUsedPlaceholders() {
		return new HashSet<>(activePlaceholderMap.values());
	}

	Set<ComponentPlaceholder> getUnusedPlaceholders() {
		return unusedPlaceholders;
	}

	ComponentPlaceholder getPlaceholder(ComponentProvider provider) {
		return activePlaceholderMap.get(provider);
	}

	boolean containsPlaceholder(ComponentProvider provider) {
		return activePlaceholderMap.containsKey(provider);
	}

	void resetPlaceholdersWithoutProviders() {
		for (ComponentPlaceholder placeholder : unusedPlaceholders) {
			if (!placeholder.hasProvider()) {
				placeholder.reset();
			}
		}
	}

	void clear() {
		activePlaceholderMap.clear();
		unusedPlaceholders.clear();
	}

	Map<ComponentProvider, ComponentPlaceholder> getProviderMap() {
		return activePlaceholderMap;
	}

	void remove(ComponentPlaceholder oldPlaceholder) {

		ComponentProvider provider = oldPlaceholder.getProvider();
		ComponentPlaceholder currentPlaceholder = activePlaceholderMap.get(provider);
		if (currentPlaceholder == oldPlaceholder) {
			activePlaceholderMap.remove(provider);
		}

		unusedPlaceholders.remove(oldPlaceholder);
		manager.disposePlaceholder(oldPlaceholder, false);
	}

	void removeAll() {
		// copy the set to prevent concurrent modifications
		Set<Entry<ComponentProvider, ComponentPlaceholder>> entries =
			new HashSet<>(
				activePlaceholderMap.entrySet());

		for (Entry<ComponentProvider, ComponentPlaceholder> entry : entries) {
			ComponentPlaceholder placeholder = entry.getValue();
			manager.disposePlaceholder(placeholder, false);
		}
		activePlaceholderMap.clear();

		for (ComponentPlaceholder placeholder : unusedPlaceholders) {
			manager.disposePlaceholder(placeholder, false);
		}
		unusedPlaceholders.clear();
	}

	private boolean containsAnyMatchingPlaceholder(ComponentPlaceholder matchee) {
		// take advantage of short-circuit ORing
		return containsMatchingUnusedPlaceholder(matchee) ||
			containsMatchingActivePlaceholder(matchee);
	}

	private boolean containsMatchingActivePlaceholder(ComponentPlaceholder matchee) {
		Collection<ComponentPlaceholder> activePlaceholders = activePlaceholderMap.values();
		return getMatchingPlaceholders(activePlaceholders, matchee) != null;
	}

	private boolean containsMatchingUnusedPlaceholder(ComponentPlaceholder matchee) {
		return getMatchingUnusedPlaceholder(matchee) != null;
	}

	private ComponentPlaceholder getMatchingUnusedPlaceholder(ComponentPlaceholder matchee) {
		return getMatchingPlaceholders(unusedPlaceholders, matchee);
	}

	private ComponentPlaceholder getMatchingPlaceholders(
			Collection<ComponentPlaceholder> placeholders, ComponentPlaceholder matchee) {

		String name = matchee.getName();
		String group = matchee.getGroup();
		Iterator<ComponentPlaceholder> it = placeholders.iterator();
		while (it.hasNext()) {
			ComponentPlaceholder placeholder = it.next();
			if (placeholder.getName().equals(name) && placeholder.getGroup().equals(group)) {
				return placeholder;
			}
		}
		return null;
	}
}
