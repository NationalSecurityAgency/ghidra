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

import docking.action.DockingActionIf;

/**
 * Managers {@link ComponentPlaceholder}s.  This includes creating them, saving placeholders
 * for later reuse and disposal.
 */
class PlaceholderManager {

	private Map<String, PlaceholderSet> ownerToPlaceholderMap =
		new HashMap<>();
	private PlaceholderInstaller installer;

	PlaceholderManager(PlaceholderInstaller installer) {
		this.installer = installer;
	}

	PlaceholderManager(PlaceholderInstaller installer,
			List<ComponentPlaceholder> restoredPlaceholders) {
		this(installer);
		for (ComponentPlaceholder placeholder : restoredPlaceholders) {
			PlaceholderSet placeholderSet = getOrCreatePlaceholderSet(placeholder.getOwner());
			placeholderSet.addRestoredPlaceholder(placeholder);
		}
	}

	ComponentPlaceholder replacePlaceholder(ComponentProvider provider,
			ComponentPlaceholder oldPlaceholder) {

		ComponentPlaceholder newPlaceholder = createOrRecyclePlaceholder(provider, oldPlaceholder);

		moveActions(oldPlaceholder, newPlaceholder);
		if (!oldPlaceholder.isHeaderShowing()) {
			newPlaceholder.showHeader(false);
		}

		if (oldPlaceholder.isShowing() != newPlaceholder.isShowing()) {
			if (newPlaceholder.isShowing()) {
				provider.componentShown();
			}
			else {
				provider.componentHidden();
			}
		}

		if (newPlaceholder != oldPlaceholder) {
			oldPlaceholder.dispose();
			removePlaceholder(oldPlaceholder);
		}
		return newPlaceholder;
	}

	/**
	 * Moves all the actions associated with the old placeholder into the new placeholder.
	 * @param oldPlaceholder the old component placeholder being replaced.
	 * @param newPlaceholder the new component placeholder.
	 */
	private void moveActions(ComponentPlaceholder oldPlaceholder,
			ComponentPlaceholder newPlaceholder) {
		if (newPlaceholder == oldPlaceholder) {
			return;
		}
		Iterator<DockingActionIf> it = oldPlaceholder.getActions();
		while (it.hasNext()) {
			DockingActionIf action = it.next();
			newPlaceholder.addAction(action);
		}
	}

	private void registerPlaceholder(ComponentPlaceholder placeholder) {

		ComponentProvider provider = placeholder.getProvider();
		String owner = provider.getOwner();
		PlaceholderSet placeholderSet = ownerToPlaceholderMap.get(owner);
		if (placeholderSet == null) {
			placeholderSet = new PlaceholderSet(this);
			ownerToPlaceholderMap.put(owner, placeholderSet);
		}

		placeholderSet.placeholderUsed(provider, placeholder);
	}

	private void removePlaceholder(ComponentPlaceholder placeholder) {
		ComponentProvider provider = placeholder.getProvider();
		String owner = provider.getOwner();
		PlaceholderSet placeholderSet = ownerToPlaceholderMap.get(owner);
		if (placeholderSet == null) {
			return;
		}

		placeholderSet.remove(placeholder);
	}

	ComponentPlaceholder createOrRecyclePlaceholder(ComponentProvider provider) {
		return createOrRecyclePlaceholder(provider, null /*no default*/);
	}

	/**
	 * Finds or creates a component placeholder object for the given provider.
	 * @param provider the provider for which to get an placeholder object.
	 * @param defaultPlaceholder the placeholder to use if an existing one cannot be found
	 * @return a component placeholder object that will be used to manager the providers component.
	 */
	ComponentPlaceholder createOrRecyclePlaceholder(ComponentProvider provider,
			ComponentPlaceholder defaultPlaceholder) {

		String owner = provider.getOwner();
		Set<ComponentPlaceholder> unusedPlaceholders = getUnusedPlaceholdersByOwner(owner);
		ComponentPlaceholder reusablePlaceholder =
			findBestUnusedPlaceholder(unusedPlaceholders, provider);

		if (reusablePlaceholder != null) {
			reusablePlaceholder.setProvider(provider);
			registerPlaceholder(reusablePlaceholder);
			return reusablePlaceholder;
		}

		ComponentPlaceholder newPlaceholder = defaultPlaceholder;
		if (newPlaceholder == null) {
			newPlaceholder = new ComponentPlaceholder(provider);
		}

		installPlaceholder(newPlaceholder);
		return newPlaceholder;
	}

	private void installPlaceholder(ComponentPlaceholder placeholder) {

		Set<ComponentPlaceholder> activePlaceholders =
			getActivePlaceholdersByOwner(placeholder.getOwner());
		registerPlaceholder(placeholder);
		positionNewPlaceholder(activePlaceholders, placeholder);
	}

	private void positionNewPlaceholder(Set<ComponentPlaceholder> activePlaceholders,
			ComponentPlaceholder newPlaceholder) {

		// first, see if we can stack the placeholder onto other, similar placeholders
		ComponentPlaceholder stackUponPlaceholder =
			findBestPlaceholderToStackUpon(activePlaceholders, newPlaceholder);
		if (stackUponPlaceholder != null) {
			stackUponPlaceholder.getNode().add(newPlaceholder);
			return;
		}

		WindowPosition windowPosition = newPlaceholder.getProvider().getDefaultWindowPosition();
		if (windowPosition == null) {
			// Error condition when provider return null
			windowPosition = WindowPosition.WINDOW;
		}

		// next, see if there is a logical anchor next to which we can put the new placeholder
		ComponentPlaceholder relativePlaceholder =
			findBestPlaceholderAnchor(activePlaceholders, newPlaceholder);
		if (relativePlaceholder == null) {
			// nothing better found, add it to the root node
			installer.installPlaceholder(newPlaceholder, windowPosition);
			return;
		}

		// are the groups the same?
		String newGroup = newPlaceholder.getGroup();
		String existingGroup = relativePlaceholder.getGroup();
		if (newGroup.equals(existingGroup)) {
			positionInSameGroup(newPlaceholder, relativePlaceholder);
		}
		else {
			positionInRelativeGroup(newPlaceholder, relativePlaceholder);
		}
	}

	private void positionInSameGroup(ComponentPlaceholder newPlaceholder,
			ComponentPlaceholder relativePlaceholder) {

		// use the relative placeholder and the 'intra' group information for placement
		ComponentNode node = relativePlaceholder.getNode();
		WindowPosition intraGroupPosition = newPlaceholder.getProvider().getIntraGroupPosition();
		if (intraGroupPosition == WindowPosition.STACK) {
			node.add(newPlaceholder);
		}
		else {
			node.split(newPlaceholder, intraGroupPosition);
		}
	}

	private void positionInRelativeGroup(ComponentPlaceholder newPlaceholder,
			ComponentPlaceholder relativePlaceholder) {

		// use the relative placeholder and the 'intra' group information for placement
		ComponentNode node = relativePlaceholder.getNode();
		ComponentProvider provider = newPlaceholder.getProvider();
		WindowPosition windowPosition = provider.getDefaultWindowPosition();
		WindowPosition intraGroupPosition = provider.getIntraGroupPosition();
		if (windowPosition == WindowPosition.WINDOW) {
			// always honor 'window' when we are not in the exact same group (note: at the time
			// of writing this, I could not think of a use case to contradict this decision).
			node.split(newPlaceholder, intraGroupPosition);
			return;
		}

		if (intraGroupPosition == WindowPosition.STACK) {
			node.add(newPlaceholder);
		}
		else {
			node.split(newPlaceholder, intraGroupPosition);
		}
	}

	private ComponentPlaceholder findBestPlaceholderAnchor(
			Set<ComponentPlaceholder> activePlaceholders, ComponentPlaceholder newPlaceholder) {

		String group = newPlaceholder.getGroup();
		if (ComponentProvider.DEFAULT_WINDOW_GROUP.equals(group)) {
			return null; // do not place together providers without a group
		}

		ComponentPlaceholder bestMatchPlaceholder = null;

		//
		// Prefer the given placeholders, if any exist.  The goal is to place providers together
		// when they:
		// 1) share the same owner (plugin), and
		// 2) are in the same group, or related groups
		//
		// If there are not other providers that share the same owner as the one we are given, 
		// then we will search all providers.  This allows different plugins to share 
		// window arrangement.
		//
		Set<ComponentPlaceholder> buddies = activePlaceholders;
		if (buddies.isEmpty()) {
			// no existing placeholders *with the same owner*--try searching all placeholders,
			// so that we can match providers' window groups across plugins.
			buddies = getAllActivePlaceholders();
		}

		for (ComponentPlaceholder placeholder : buddies) {
			if (placeholder == newPlaceholder) {
				continue;
			}

			String testGroup = placeholder.getGroup();
			if (group.startsWith(testGroup)) {
				if (bestMatchPlaceholder == null ||
					testGroup.length() > bestMatchPlaceholder.getGroup().length()) {
					bestMatchPlaceholder = placeholder;
				}
			}
		}

		return bestMatchPlaceholder;
	}

	/**
	 * Look for placeholder with the same name and group.  If such a placeholder exists, then
	 * there is already at least one instance of this provider showing and we will stack the
	 * new provider on top of this one, ignoring any windowing positioning specified by the new
	 * provider.
	 * @param activePlaceholders the set of currently showing placeholders.
	 * @param newInfo the placeholder for the new provider to be shown.
	 * @return an existing matching placeholder or null. 
	 */
	private ComponentPlaceholder findBestPlaceholderToStackUpon(
			Set<ComponentPlaceholder> activePlaceholders, ComponentPlaceholder newInfo) {

		String name = newInfo.getName();
		String group = newInfo.getGroup();

		for (ComponentPlaceholder placeholder : activePlaceholders) {
			if (name.equals(placeholder.getName()) && group.equals(placeholder.getGroup())) {
				return placeholder;
			}
		}

		return null;
	}

	private ComponentPlaceholder findBestUnusedPlaceholder(
			Set<ComponentPlaceholder> unusedPlaceholders, ComponentProvider provider) {

		String name = provider.getName();
		String windowGroup = provider.getWindowGroup();
		boolean isInvalid = windowGroup == null || windowGroup.trim().isEmpty();

		String group = isInvalid ? ComponentProvider.DEFAULT_WINDOW_GROUP : windowGroup;

		// look for a match based on name and title, first prefer a visible one.
		String title = provider.getTitle();
		for (ComponentPlaceholder placeholder : unusedPlaceholders) {
			if (placeholder.wantsToBeShowing() && name.equals(placeholder.getName()) &&
				title.equals(placeholder.getTitle())) {
				return placeholder;
			}
		}

		// look for a match based upon name and title, now accept one that is not showing.
		for (ComponentPlaceholder placeholder : unusedPlaceholders) {
			if (name.equals(placeholder.getName()) && title.equals(placeholder.getTitle())) {
				return placeholder;
			}
		}

		// look for a "close enough" match (same name and group)
		for (ComponentPlaceholder placeholder : unusedPlaceholders) {
			if (name.equals(placeholder.getName()) && group.equals(placeholder.getGroup())) {
				return placeholder;
			}
		}

		return null;
	}

	private Set<ComponentPlaceholder> getUnusedPlaceholdersByOwner(String owner) {
		PlaceholderSet placeholderSet = getOrCreatePlaceholderSet(owner);
		return placeholderSet.getUnusedPlaceholders();
	}

	private Set<ComponentPlaceholder> getActivePlaceholdersByOwner(String owner) {
		PlaceholderSet placeholderSet = getOrCreatePlaceholderSet(owner);
		return placeholderSet.getUsedPlaceholders();
	}

	void disposePlaceholder(ComponentPlaceholder placeholder, boolean keepAround) {
		installer.uninstallPlaceholder(placeholder, keepAround);
	}

	boolean containsProvider(ComponentProvider provider) {
		String owner = provider.getOwner();
		PlaceholderSet placeholderSet = getOrCreatePlaceholderSet(owner);
		return placeholderSet.containsPlaceholder(provider);
	}

	private PlaceholderSet getOrCreatePlaceholderSet(String owner) {
		PlaceholderSet placeholderSet = ownerToPlaceholderMap.get(owner);
		if (placeholderSet != null) {
			return placeholderSet;
		}

		placeholderSet = new PlaceholderSet(this);
		ownerToPlaceholderMap.put(owner, placeholderSet);
		return placeholderSet;
	}

	ComponentPlaceholder getActivePlaceholder(ComponentProvider provider) {
		if (provider == null) {
			return null;
		}
		PlaceholderSet placeholderSet = getOrCreatePlaceholderSet(provider.getOwner());
		return placeholderSet.getPlaceholder(provider);
	}

	Map<ComponentProvider, ComponentPlaceholder> getActiveProvidersToPlaceholders() {
		Map<ComponentProvider, ComponentPlaceholder> map =
			new HashMap<>();
		Iterator<PlaceholderSet> placeholderIterator = ownerToPlaceholderMap.values().iterator();
		while (placeholderIterator.hasNext()) {
			PlaceholderSet placeholders = placeholderIterator.next();
			map.putAll(placeholders.getProviderMap());
		}
		return map;
	}

	private Set<ComponentPlaceholder> getAllActivePlaceholders() {

		Set<ComponentPlaceholder> set = new HashSet<>();
		Iterator<PlaceholderSet> placeholderIterator = ownerToPlaceholderMap.values().iterator();
		while (placeholderIterator.hasNext()) {
			PlaceholderSet placeholders = placeholderIterator.next();
			set.addAll(placeholders.getUsedPlaceholders());
		}
		return set;
	}

	Set<ComponentProvider> getActiveProviders() {
		return getActiveProvidersToPlaceholders().keySet();
	}

	ComponentPlaceholder getPlaceholder(ComponentProvider provider) {
		Map<ComponentProvider, ComponentPlaceholder> map = getActiveProvidersToPlaceholders();
		return map.get(provider);
	}

	void removeComponent(ComponentProvider provider) {
		PlaceholderSet placeholderSet = getOrCreatePlaceholderSet(provider.getOwner());
		placeholderSet.placeholderFreed(provider);
	}

	void removeAll(String owner) {
		PlaceholderSet placeholderSet = getOrCreatePlaceholderSet(owner);
		placeholderSet.removeAll();
	}

	void clearActivePlaceholders() {
		ownerToPlaceholderMap.clear();
	}

	void disposePlaceholders() {
		Collection<PlaceholderSet> values = ownerToPlaceholderMap.values();
		for (PlaceholderSet placeholderSet : values) {
			placeholderSet.clear();
		}
		ownerToPlaceholderMap.clear();
	}

	void resetPlaceholdersWithoutProviders() {
		Collection<PlaceholderSet> placeholderSets = ownerToPlaceholderMap.values();
		for (PlaceholderSet placeholderSet : placeholderSets) {
			placeholderSet.resetPlaceholdersWithoutProviders();
		}
	}
}
