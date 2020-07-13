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
package ghidra.app.plugin.core.totd;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Tip Of The Day",
	description = "Display a dialog containing 'Tips of the Day'."
)
//@formatter:on
public class TipOfTheDayPlugin extends Plugin implements FrontEndOnly {
	private static final String TIP_INDEX = "TIP_INDEX";
	private static final String SHOW_TIPS = "SHOW_TIPS";

	private TipOfTheDayDialog dialog;
	private DockingAction action;

	public TipOfTheDayPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		action = new DockingAction("Tips of the day", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				dialog.doShow(tool.getToolFrame());
			}
		};
		action.setMenuBarData(new MenuData(new String[] { "Help", "Tip of the Day" },
			ToolConstants.HELP_CONTENTS_MENU_GROUP));

		action.setEnabled(true);
		action.setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Tip_of_the_day"));
		tool.addAction(action);

		List<String> tips = null;
		try {
			tips = loadTips();
		}
		catch (IOException e) {
			tips = new ArrayList<>();
		}
		dialog = new TipOfTheDayDialog(this, tips);

		readPreferences();
	}

	private List<String> loadTips() throws IOException {
		try (InputStream in = getClass().getResourceAsStream("tips.txt")) {
			List<String> tips = in == null ? Collections.emptyList() : FileUtilities.getLines(in);
			return tips.stream().filter(s -> s.length() > 0).collect(Collectors.toList());
		}
	}

	@Override
	protected void dispose() {
		writePreferences();

		action.dispose();
		dialog.close();
	}

	private void readPreferences() {
		String tipIndexStr = Preferences.getProperty(TIP_INDEX, "0", true);
		String showTipsStr = Preferences.getProperty(SHOW_TIPS, "true", true);

		int tipIndex = Integer.parseInt(tipIndexStr);
		final boolean showTips = Boolean.parseBoolean(showTipsStr);
		if (showTips) {
			tipIndex = (++tipIndex) % dialog.getNumberOfTips();
			writePreferences(tipIndex, showTips);
		}

		dialog.setTipIndex(tipIndex);
		dialog.setShowTips(showTips);

		SystemUtilities.runSwingLater(() -> {
			if (showTips && !SystemUtilities.isInTestingMode()) {
				dialog.show(tool.getToolFrame());
			}
			else {
				dialog.close();
			}
		});
	}

	void writePreferences() {
		if (dialog != null) {
			writePreferences(dialog.getTipIndex(), dialog.showTips());
		}
	}

	private void writePreferences(int tipIndex, boolean showTips) {
		Preferences.setProperty(TIP_INDEX, "" + tipIndex);
		Preferences.setProperty(SHOW_TIPS, "" + showTips);
		Preferences.store();
	}
}
