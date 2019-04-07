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
package ghidra.bitpatterns.gui;

import java.util.*;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.util.ProgramSelection;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "FunctionBitPatternsExplorerPlugin",
	description = "Plugin for exploring function start/return patterns."
)
//@formatter:on
public class FunctionBitPatternsExplorerPlugin extends ProgramPlugin {

	private FunctionBitPatternsMainProvider provider;

	//patterns selected by the user

	private Set<PatternInfoRowObject> patterns;

	/**
	 * Creates the plugin
	 * @param tool tool
	 */
	public FunctionBitPatternsExplorerPlugin(PluginTool tool) {
		super(tool, false, false);
		provider = new FunctionBitPatternsMainProvider(this);
		patterns = new HashSet<>();
	}

	/**
	 * Add a pattern to the set of patterns
	 * @param patternRow
	 */
	public void addPattern(PatternInfoRowObject patternRow) {
		patterns.add(patternRow);
	}

	/**
	 * Remove the specified patterns
	 * @param patternsToRemove patterns to remove
	 */
	public void removePatterns(Collection<PatternInfoRowObject> patternsToRemove) {
		patterns.removeAll(patternsToRemove);
	}

	/**
	 * Get the patterns
	 * @return patterns
	 */
	public Set<PatternInfoRowObject> getPatterns() {
		return new HashSet<>(patterns);
	}

	/**
	 * Clear the patterns
	 */
	public void clearPatterns() {
		patterns.clear();
	}

	void updateClipboard() {
		provider.updateClipboard();
	}

	void highlightMatches(AddressSetView matches) {
		ProgramSelection highlighted = new ProgramSelection(matches);
		ProgramHighlightPluginEvent highLightEvent =
			new ProgramHighlightPluginEvent(getName(), highlighted, this.getCurrentProgram());
		firePluginEvent(highLightEvent);
	}

	@Override
	protected void dispose() {
		if (provider != null) {
			provider.dispose();
		}
	}

}
