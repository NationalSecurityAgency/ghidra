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
package ghidra.features.base.memsearch.gui;

import java.nio.charset.Charset;
import java.util.*;
import java.util.function.Consumer;

import ghidra.features.base.memsearch.bytesource.SearchRegion;
import ghidra.features.base.memsearch.combiner.Combiner;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.matcher.ByteMatcher;

/**
 * Maintains the state of all the settings and controls for the memory search window.
 */
public class SearchGuiModel {

	private SearchSettings settings;
	private List<Consumer<SearchSettings>> changeCallbacks = new ArrayList<>();
	private boolean hasSelection;
	private List<SearchRegion> regionChoices;
	private boolean autoResrictSelection = false;
	private boolean isSearchSelectionOnly;
	private Combiner combiner;

	public SearchGuiModel(SearchSettings settings, List<SearchRegion> regionChoices) {
		this.regionChoices = regionChoices;
		// make a copy of settings so they don't change out from under us
		this.settings = settings != null ? settings : new SearchSettings();
		if (!isValidRegionSettings() || this.settings.getSelectedMemoryRegions().isEmpty()) {
			installDefaultRegions();
		}
	}

	private void installDefaultRegions() {
		Set<SearchRegion> defaultRegions = new HashSet<>();
		for (SearchRegion region : regionChoices) {
			if (region.isDefault()) {
				defaultRegions.add(region);
			}
		}
		settings = settings.withSelectedRegions(defaultRegions);
	}

	private boolean isValidRegionSettings() {
		for (SearchRegion region : settings.getSelectedMemoryRegions()) {
			if (!regionChoices.contains(region)) {
				return false;
			}
		}
		return true;
	}

	public void setAutoRestrictSelection() {
		autoResrictSelection = true;
	}

	public void addChangeCallback(Consumer<SearchSettings> changeCallback) {
		changeCallbacks.add(changeCallback);
	}

	private void notifySettingsChanged(SearchSettings oldSettings) {
		for (Consumer<SearchSettings> callback : changeCallbacks) {
			callback.accept(oldSettings);
		}
	}

	public boolean isSearchSelectionOnly() {
		return isSearchSelectionOnly;
	}

	public boolean hasSelection() {
		return hasSelection;
	}

	public void setHasSelection(boolean b) {
		if (hasSelection == b) {
			return;
		}
		hasSelection = b;
		if (b) {
			if (autoResrictSelection) {
				// autoRestrictSelection means to auto turn on restrict search to selection when
				// a selection happens
				isSearchSelectionOnly = true;
			}
		}
		else {
			// if no selection, then we can't search in a selection!
			isSearchSelectionOnly = false;
		}

		notifySettingsChanged(settings);
	}

	public void setSearchSelectionOnly(boolean b) {
		if (isSearchSelectionOnly == b) {
			return;
		}
		// can only set it if there is a current selection
		isSearchSelectionOnly = b && hasSelection;
		notifySettingsChanged(settings);
	}

	public SearchFormat getSearchFormat() {
		return settings.getSearchFormat();
	}

	public SearchSettings getSettings() {
		return settings;
	}

	public void setSearchFormat(SearchFormat searchFormat) {
		if (searchFormat == settings.getSearchFormat()) {
			return;
		}
		SearchSettings oldSettings = settings;
		settings = settings.withSearchFormat(searchFormat);
		notifySettingsChanged(oldSettings);
	}

	public ByteMatcher parse(String proposedText) {
		return settings.getSearchFormat().parse(proposedText, settings);
	}

	public int getAlignment() {
		return settings.getAlignment();
	}

	public void setAlignment(int alignment) {
		settings = settings.withAlignment(alignment);
		// this setting doesn't affect any other gui state, so no need to notify change
	}

	public Set<SearchRegion> getSelectedMemoryRegions() {
		return settings.getSelectedMemoryRegions();
	}

	public boolean includeInstructions() {
		return settings.includeInstructions();
	}

	public boolean includeDefinedData() {
		return settings.includeDefinedData();
	}

	public boolean includeUndefinedData() {
		return settings.includeUndefinedData();
	}

	public void setIncludeInstructions(boolean selected) {
		settings = settings.withIncludeInstructions(selected);
	}

	public void setIncludeDefinedData(boolean selected) {
		settings = settings.withIncludeDefinedData(selected);
	}

	public void setIncludeUndefinedData(boolean selected) {
		settings = settings.withIncludeUndefinedData(selected);
	}

	public boolean isBigEndian() {
		return settings.isBigEndian();
	}

	public void setBigEndian(boolean b) {
		if (settings.isBigEndian() == b) {
			return;
		}
		SearchSettings oldSettings = settings;
		settings = settings.withBigEndian(b);
		notifySettingsChanged(oldSettings);
	}

	public boolean isCaseSensitive() {
		return settings.isCaseSensitive();
	}

	public void setCaseSensitive(boolean selected) {
		if (settings.isCaseSensitive() == selected) {
			return;
		}
		SearchSettings oldSettings = settings;
		settings = settings.withCaseSensitive(selected);
		notifySettingsChanged(oldSettings);
	}

	public boolean useEscapeSequences() {
		return settings.useEscapeSequences();
	}

	public void setUseEscapeSequences(boolean selected) {
		if (settings.useEscapeSequences() == selected) {
			return;
		}
		SearchSettings oldSettings = settings;
		settings = settings.withUseEscapeSequence(selected);
		notifySettingsChanged(oldSettings);
	}

	public void setDecimalUnsigned(boolean selected) {
		if (settings.isDecimalUnsigned() == selected) {
			return;
		}
		SearchSettings oldSettings = settings;
		settings = settings.withDecimalUnsigned(selected);
		notifySettingsChanged(oldSettings);
	}

	public boolean isDecimalUnsigned() {
		return settings.isDecimalUnsigned();
	}

	public void setDecimalByteSize(int byteSize) {
		if (settings.getDecimalByteSize() == byteSize) {
			return;
		}
		SearchSettings oldSettings = settings;
		settings = settings.withDecimalByteSize(byteSize);
		notifySettingsChanged(oldSettings);
	}

	public int getDecimalByteSize() {
		return settings.getDecimalByteSize();
	}

	public void setStringCharset(Charset charset) {
		if (settings.getStringCharset() == charset) {
			return;
		}
		SearchSettings oldSettings = settings;
		settings = settings.withStringCharset(charset);
		notifySettingsChanged(oldSettings);
	}

	public Charset getStringCharset() {
		return settings.getStringCharset();
	}

	public List<SearchRegion> getMemoryRegionChoices() {
		return regionChoices;
	}

	public void setMatchCombiner(Combiner combiner) {
		this.combiner = combiner;
	}

	public Combiner getMatchCombiner() {
		return combiner;
	}

	public void setAutoRestrictSelection(boolean autoRestrictSelection) {
		this.autoResrictSelection = autoRestrictSelection;
	}

	public void selectRegion(SearchRegion region, boolean selected) {
		settings.withSelectedRegion(region, selected);
	}

	public boolean isSelectedRegion(SearchRegion region) {
		return settings.isSelectedRegion(region);
	}

	public void setSettings(SearchSettings newSettings) {
		SearchSettings oldSettings = settings;
		settings = newSettings;
		if (!isValidRegionSettings() || this.settings.getSelectedMemoryRegions().isEmpty()) {
			installDefaultRegions();
		}
		notifySettingsChanged(oldSettings);
	}
}
