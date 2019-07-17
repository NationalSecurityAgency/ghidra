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

import static ghidra.feature.vt.gui.filters.Filter.FilterEditingStatus.APPLIED;
import static ghidra.feature.vt.gui.filters.Filter.FilterEditingStatus.NONE;

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.impl.VersionTrackingChangeRecord;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTControllerListener;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;

public class TagFilter extends AncillaryFilter<VTMatch> {

	private static final String ALL_TAGS_INCLUDED = "<All Tags Included>";
	private static final String ALL_TAGS_EXCLUDED = "<All Tags Excluded>";
	static final String EXCLUDED_TAGS_KEY = "TagFilter.tags";
	private static final String DELIMITER = ":";
	private Map<String, VTMatchTag> excludedTags = new TreeMap<>(); // ordered by String
	private JLabel excludedTagsLabel = new GDLabel();
	private JComponent component;

	private final VTController controller;
	private final TagFilterChooser tagChooser;
	private JButton editButton;

	public TagFilter(VTController controller) {
		this(controller, new TagFilterEditorDialog(controller));
	}

	TagFilter(VTController controller, TagFilterChooser tagChooser) {
		this.controller = controller;
		this.tagChooser = tagChooser;
		controller.addListener(new TagUpdateListener());
		component = createComponent();
		initializeTags();
	}

	private JComponent createComponent() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Tags"));

		editButton = new JButton("Edit");
		editButton.addActionListener(e -> chooseExcludedTags());

		editButton.setEnabled(false);

		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BoxLayout(innerPanel, BoxLayout.X_AXIS));
		innerPanel.add(new GLabel("Excluded Tags: "));
		innerPanel.add(excludedTagsLabel);
		innerPanel.add(Box.createHorizontalGlue());
		innerPanel.add(editButton);
		panel.add(innerPanel, BorderLayout.NORTH);

		return panel;
	}

	private void chooseExcludedTags() {
		Map<String, VTMatchTag> allTags = getAllTags();
		excludedTags = tagChooser.getExcludedTags(allTags, new TreeMap<>(excludedTags));
		updateTags(allTags);
	}

	private void initializeTags() {
		// allow all tags by default
		excludedTags = new TreeMap<>();
		updateTags();
	}

	/**
	 * This differs from {@link #initializeTags()} in that this method will keep any excluded 
	 * tags when updating.
	 */
	private void reInitializeTags() {
		updateTags(getAllTags());
	}

	private void updateTags() {
		updateTags(getAllTags());
	}

	private void updateTags(Map<String, VTMatchTag> allTags) {
		fireStatusChanged(getFilterStatus());

		if (excludedTags.size() == 0) {
			excludedTagsLabel.setText(ALL_TAGS_INCLUDED);
			return;
		}

		if (excludedTags.size() == allTags.size()) {
			excludedTagsLabel.setText(ALL_TAGS_EXCLUDED);
			return;
		}

		String tagText = getTagText(excludedTags);
		excludedTagsLabel.setText(tagText.replaceAll(DELIMITER, ", "));
	}

	private Map<String, VTMatchTag> getAllTags() {
		VTSession session = controller.getSession();
		if (session == null) {
			return Collections.emptyMap();
		}
		TreeMap<String, VTMatchTag> map = new TreeMap<>();

		Set<VTMatchTag> matchTags = session.getMatchTags();
		for (VTMatchTag tag : matchTags) {
			map.put(tag.getName(), tag);
		}

		map.put(VTMatchTag.UNTAGGED.getName(), VTMatchTag.UNTAGGED);

		return map;
	}

	private void tagAdded(VTMatchTag tag) {
		updateTags();
	}

	private void tagRemoved(String tagName) {
		excludedTags.remove(tagName); // call in case it is excluded
		updateTags();
	}

	@Override
	public FilterState getFilterState() {
		FilterState state = new FilterState(this);
		state.put(EXCLUDED_TAGS_KEY, new TreeMap<>(excludedTags));
		return state;
	}

	@Override
	public FilterShortcutState getFilterShortcutState() {

		if (excludedTags.size() == 0) {
			return FilterShortcutState.ALWAYS_PASSES;
		}

		Map<String, VTMatchTag> allTags = getAllTags();
		if (allTags.size() == excludedTags.size()) {
			return FilterShortcutState.NEVER_PASSES;
		}

		return FilterShortcutState.REQUIRES_CHECK;
	}

	private String getTagText(Map<String, VTMatchTag> tags) {
		StringBuilder buildy = new StringBuilder();

		Collection<VTMatchTag> values = tags.values();
		for (VTMatchTag tag : values) {
			String tagText = tag.getName();
			if (tag == VTMatchTag.UNTAGGED) {
				tagText = VTMatchTag.UNTAGGED.toString();
			}
			buildy.append(tagText).append(DELIMITER);
		}

		// strip off last delimiter
		if (buildy.length() > 0) {
			int lastDelimiter = buildy.lastIndexOf(DELIMITER);
			buildy.delete(lastDelimiter, buildy.length());
		}

		return buildy.toString();
	}

	private Map<String, VTMatchTag> getTagsFromText(String tagText) {
		Map<String, VTMatchTag> allTags = getAllTags();
		Map<String, VTMatchTag> tagFromStringMap = new TreeMap<>();
		String[] tags = tagText.split(DELIMITER);
		for (String tagString : tags) {
			VTMatchTag tag = allTags.get(tagString);
			if (tag != null) {
				tagFromStringMap.put(tagString, tag);
			}
		}
		return tagFromStringMap;
	}

	@SuppressWarnings("unchecked")
	// cast to map is safe since we put the map in earlier
	@Override
	public void restoreFilterState(FilterState state) {
		Map<String, VTMatchTag> storedExcludedTags =
			(Map<String, VTMatchTag>) state.get(EXCLUDED_TAGS_KEY);
		excludedTags.clear();
		if (storedExcludedTags != null) {
			excludedTags.putAll(storedExcludedTags);
		}

		updateTags();
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		removeOldTags(); // don't persist tags that no longer exist
		String tagText = getTagText(excludedTags);
		saveState.putString(getStateKey(), tagText);
	}

	private String getStateKey() {
		return getClass().getName();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String tagText = saveState.getString(getStateKey(), null);
		if (tagText == null) {
			return;
		}

		excludedTags = getTagsFromText(tagText);
	}

	@Override
	public void clearFilter() {
		excludedTags.clear();
		excludedTagsLabel.setText(ALL_TAGS_INCLUDED);
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public FilterEditingStatus getFilterStatus() {
		if (excludedTags.size() != 0) {
			return APPLIED;
		}
		return NONE;
	}

	@Override
	public boolean passesFilter(VTMatch t) {
		VTMatchTag tag = t.getTag();
		return !excludedTags.containsKey(tag.getName());
	}

	private void removeOldTags() {
		Map<String, VTMatchTag> allTags = getAllTags();
		Iterator<VTMatchTag> iterator = excludedTags.values().iterator();
		for (; iterator.hasNext();) {
			VTMatchTag tag = iterator.next();
			if (!allTags.containsKey(tag.getName())) {
				// not in the new session
				excludedTags.remove(tag.getName());
			}
		}
	}

	@Override
	public boolean isSubFilterOf(Filter<VTMatch> otherFilter) {

		Class<?> clazz = getClass();
		Class<?> otherClazz = otherFilter.getClass();
		if (!clazz.equals(otherClazz)) {
			return false; // must be the same class
		}

		TagFilter otherTagFilter = (TagFilter) otherFilter;
		Set<String> names = excludedTags.keySet();
		Set<String> otherNames = otherTagFilter.excludedTags.keySet();

		// 
		// This filter is a collection of 'things', that are NOT allowed to pass the filter.   
		// We are only a sub-filter if the other filter is a subset of our filter, since we will
		// be taking the already excluded items and adding more restrictions.  Suppose our filter 
		// consists of: 'cat', 'dog', 'mouse'.  We would then be a sub-filter if the other 
		// filter's set consists of: 'cat', 'dog'.
		//
		if (names.containsAll(otherNames)) {
			return true;
		}

		return false;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + ": " + excludedTags.keySet();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TagUpdateListener implements VTControllerListener {

		@Override
		public void disposed() {
			// handled by the filter interface
		}

		@Override
		public void markupItemSelected(VTMarkupItem markupItem) {
			// don't care
		}

		@Override
		public void matchSelected(MatchInfo matchInfo) {
			// don't care
		}

		@Override
		public void optionsChanged(Options options) {
			// don't care yet
		}

		@Override
		public void sessionChanged(VTSession session) {
			editButton.setEnabled(session != null);
			reInitializeTags();
		}

		@Override
		public void sessionUpdated(DomainObjectChangedEvent ev) {
			//
			// Note: we don't trigger a refilter after changes are made.  We assume that if a tag
			//       is added, then it will not be excluded by default.  If a tag is removed, 
			//       then the work to remove it will have cleared any matches using that tag, which
			//       will trigger an update to the table, which will trigger a refilter.
			// 

			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
				int eventType = doRecord.getEventType();

				if (eventType == VTChangeManager.DOCR_VT_TAG_ADDED) {
					VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
					tagAdded((VTMatchTag) vtRecord.getNewValue());
				}
				else if (eventType == VTChangeManager.DOCR_VT_TAG_REMOVED) {
					VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
					tagRemoved((String) vtRecord.getOldValue());
				}
			}
		}
	}
}
