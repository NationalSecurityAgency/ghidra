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
package ghidra.app.plugin.core.codebrowser.hover;

import static ghidra.util.HTMLUtilities.*;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.SourceMapFieldLocation;

/**
 * A hover service to show the full path of a source file field
 */
public class SourceMapFieldHover extends AbstractConfigurableHover
		implements ListingHoverService {

	private static final String NAME = "Source Map";
	private static final String DESCRIPTION =
		"Toggle whether the full source file path is shown as a tooltip.";
	private static final int PRIORITY = 20;

	public SourceMapFieldHover(PluginTool tool) {
		super(tool, PRIORITY);
	}

	@Override
	protected String getName() {
		return NAME;
	}

	@Override
	protected String getDescription() {
		return DESCRIPTION;
	}

	@Override
	protected String getOptionsCategory() {
		return GhidraOptions.CATEGORY_BROWSER_POPUPS;
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		if (!enabled || !(programLocation instanceof SourceMapFieldLocation smfLoc)) {
			return null;
		}
		
		SourceMapEntry entry = smfLoc.getSourceMapEntry();
		return createTooltipComponent("<HTML>%s:%d".formatted(
			friendlyEncodeHTML(entry.getSourceFile().getPath()), entry.getLineNumber()));
	}
}
