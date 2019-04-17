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
package ghidra.app.plugin.core.colorizer;

import java.awt.Color;
import java.util.Collections;
import java.util.List;

import docking.options.editor.GhidraColorChooser;
import ghidra.app.util.viewer.listingpanel.PropertyBasedBackgroundColorModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.IntRangeMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;

class ColorizingServiceProvider implements ColorizingService {

	private static final Color DEFAULT_COLOR = new Color(0x84AFD3);
	static final String COLOR_CHOOSER_TITLE = "Please Select Background Color";

	private final PluginTool tool;

	private GhidraColorChooser colorChooser;
	private List<Color> savedColorHistory;

	private Program program;

	ColorizingServiceProvider(PluginTool tool) {
		this.tool = tool;
	}

	void setProgram(Program program) {
		this.program = program;
	}

	@Override
	public Color getMostRecentColor() {
		List<Color> recentColors = getRecentColors();
		if (recentColors != null && recentColors.size() > 0) {
			return recentColors.get(0);
		}
		return DEFAULT_COLOR;
	}

	@Override
	public List<Color> getRecentColors() {
		if (colorChooser != null) {
			List<Color> colorHistory = colorChooser.getColorHistory();
			if (colorHistory.size() > 0) {
				return colorHistory;
			}
		}

		if (savedColorHistory == null) {
			return Collections.emptyList();
		}
		return savedColorHistory;
	}

	void setColorHistory(List<Color> colorHistory) {
		this.savedColorHistory = colorHistory;
	}

	List<Color> getColorHistory() {
		if (colorChooser == null) {
			return null; // nothing has changed
		}
		return colorChooser.getColorHistory();
	}

	@Override
	public Color getColorFromUser(Color suggestedColor) {
		if (colorChooser == null) {
			colorChooser =
				new GhidraColorChooser(suggestedColor == null ? Color.WHITE : suggestedColor);
			colorChooser.setTitle(COLOR_CHOOSER_TITLE);
			if (savedColorHistory != null) {
				colorChooser.setColorHistory(savedColorHistory);
			}
		}

		Color chosenColor = colorChooser.showDialog(null);
		maybeNotifyConfigChanged(suggestedColor, chosenColor);
		return chosenColor;
	}

	private void maybeNotifyConfigChanged(Color originalColor, Color chosenColor) {
		if (chosenColor == null) {
			// user cancelled
			return;
		}

		if (originalColor != null) {
			if (originalColor.equals(chosenColor)) {
				return;
			}
		}

		tool.setConfigChanged(true);
	}

	@Override
	public void setBackgroundColor(Address min, Address max, Color c) {
		IntRangeMap map = getColorRangeMap(true);
		if (map != null) {
			map.setValue(min, max, c.getRGB());
		}
	}

	@Override
	public void setBackgroundColor(AddressSetView set, Color c) {
		IntRangeMap map = getColorRangeMap(true);
		if (map != null) {
			map.setValue(set, c.getRGB());
		}
	}

	@Override
	public Color getBackgroundColor(Address address) {
		IntRangeMap map = getColorRangeMap(false);
		if (map != null) {
			Integer value = map.getValue(address);
			if (value != null) {
				return new Color(value, true);
			}
		}
		return null;
	}

	@Override
	public AddressSetView getAllBackgroundColorAddresses() {
		IntRangeMap map = getColorRangeMap(false);
		if (map != null) {
			return map.getAddressSet();
		}
		return new AddressSet();
	}

	@Override
	public AddressSetView getBackgroundColorAddresses(Color color) {
		IntRangeMap map = getColorRangeMap(false);
		if (map != null) {
			return map.getAddressSet(color.getRGB());
		}
		return new AddressSet();
	}

	@Override
	public void clearAllBackgroundColors() {
		IntRangeMap map = getColorRangeMap(false);
		if (map != null) {
			map.clearAll();
		}
	}

	@Override
	public void clearBackgroundColor(Address min, Address max) {
		IntRangeMap map = getColorRangeMap(false);
		if (map != null) {
			map.clearValue(min, max);
		}
	}

	@Override
	public void clearBackgroundColor(AddressSetView set) {
		IntRangeMap map = getColorRangeMap(false);
		if (map != null) {
			map.clearValue(set);
		}
	}

	private IntRangeMap getColorRangeMap(boolean create) {
		if (program == null) {
			return null;
		}
		IntRangeMap map =
			program.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
		if (map == null && create) {
			try {
				map = program.createIntRangeMap(
					PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
			}
			catch (DuplicateNameException e) {
				// can't happen since we just checked for it!
			}
		}
		return map;
	}
}
