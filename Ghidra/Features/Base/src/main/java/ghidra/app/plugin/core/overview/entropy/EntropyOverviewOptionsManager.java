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
package ghidra.app.plugin.core.overview.entropy;

import java.awt.Color;

import ghidra.app.plugin.core.overview.OverviewColorPlugin;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * Helper class for the {@link EntropyOverviewColorService} to manage the options and create
 * the color Palette for that service.
 */
public class EntropyOverviewOptionsManager implements OptionsChangeListener {
	private static final Color uninitializedColor = Color.decode("0x0000ff");
	private static final String OPTIONS_NAME = "Entropy";
	private final static String CHUNKSIZE_STRING = "Chunk size";
	private final static String CHUNKSIZE_DESC_STRING = "Number of bytes per entropy score";
	private final static EntropyChunkSize chunksize_def = EntropyChunkSize.LARGE;
	private final static String KNOT_COLOR_STRING =
		"Color to use for highlighting a specific range of entropy values";
	private final static String KNOT_TYPE_STRING = "Type of range to highlight";
	private final static String KNOT1_COLOR_STRING = "Range 1 color";
	private final static String KNOT1_TYPE_STRING = "Entropy Range 1";
	private final static Color knot1_def_color = Color.decode("0xff0000");
	private final static EntropyKnot knot1_def_type = EntropyKnot.COMPRESSED;
	private final static String KNOT2_COLOR_STRING = "Range 2 color";
	private final static String KNOT2_TYPE_STRING = "Entropy Range 2";
	private final static Color knot2_def_color = Color.decode("0x0000ff");
	private final static EntropyKnot knot2_def_type = EntropyKnot.X86;
	private final static String KNOT3_COLOR_STRING = "Range 3 color";
	private final static String KNOT3_TYPE_STRING = "Entropy Range 3";
	private final static Color knot3_def_color = Color.decode("0x00ff00");
	private final static EntropyKnot knot3_def_type = EntropyKnot.ASCII;
	private final static String KNOT4_COLOR_STRING = "Range 4 color";
	private final static String KNOT4_TYPE_STRING = "Entropy Range 4";
	private final static Color knot4_def_color = Color.decode("0xffff00");
	private final static EntropyKnot knot4_def_type = EntropyKnot.UTF16;
	private final static String KNOT5_COLOR_STRING = "Range 5 color";
	private final static String KNOT5_TYPE_STRING = "Entropy Range 5";
	private final static Color knot5_def_color = Color.decode("0x0000ff");
	private final static EntropyKnot knot5_def_type = EntropyKnot.NONE;
	private EntropyChunkSize chunksize;
	private Color knot1color;
	private EntropyKnot knot1type;
	private Color knot2color;
	private EntropyKnot knot2type;
	private Color knot3color;
	private EntropyKnot knot3type;
	private Color knot4color;
	private EntropyKnot knot4type;
	private Color knot5color;
	private EntropyKnot knot5type;
	private Palette palette = new Palette(256, uninitializedColor);
	private EntropyOverviewColorService service;

	public EntropyOverviewOptionsManager(PluginTool tool, EntropyOverviewColorService service) {
		this.service = service;
		ToolOptions options = tool.getOptions(OPTIONS_NAME);
		HelpLocation help = new HelpLocation(OverviewColorPlugin.HELP_TOPIC, "EntropyOverviewBar");

		options.addOptionsChangeListener(this);
		options.setOptionsHelpLocation(help);

		options.registerOption(CHUNKSIZE_STRING, chunksize_def, help, CHUNKSIZE_DESC_STRING);
		options.registerOption(KNOT1_COLOR_STRING, knot1_def_color, help, KNOT_COLOR_STRING);
		options.registerOption(KNOT2_COLOR_STRING, knot2_def_color, help, KNOT_COLOR_STRING);
		options.registerOption(KNOT3_COLOR_STRING, knot3_def_color, help, KNOT_COLOR_STRING);
		options.registerOption(KNOT4_COLOR_STRING, knot4_def_color, help, KNOT_COLOR_STRING);
		options.registerOption(KNOT5_COLOR_STRING, knot5_def_color, help, KNOT_COLOR_STRING);

		options.registerOption(KNOT1_TYPE_STRING, knot1_def_type, help, KNOT_TYPE_STRING);
		options.registerOption(KNOT2_TYPE_STRING, knot2_def_type, help, KNOT_TYPE_STRING);
		options.registerOption(KNOT3_TYPE_STRING, knot3_def_type, help, KNOT_TYPE_STRING);
		options.registerOption(KNOT4_TYPE_STRING, knot4_def_type, help, KNOT_TYPE_STRING);
		options.registerOption(KNOT5_TYPE_STRING, knot5_def_type, help, KNOT_TYPE_STRING);

		readOptions(options);
		updatePalettes();
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		readOptions(options);
		updatePalettes();
	}

	private void readOptions(ToolOptions options) {
		chunksize = options.getEnum(CHUNKSIZE_STRING, chunksize_def);

		knot1color = options.getColor(KNOT1_COLOR_STRING, knot1_def_color);
		knot2color = options.getColor(KNOT2_COLOR_STRING, knot2_def_color);
		knot3color = options.getColor(KNOT3_COLOR_STRING, knot3_def_color);
		knot4color = options.getColor(KNOT4_COLOR_STRING, knot4_def_color);
		knot5color = options.getColor(KNOT5_COLOR_STRING, knot5_def_color);

		knot1type = options.getEnum(KNOT1_TYPE_STRING, knot1_def_type);
		knot2type = options.getEnum(KNOT2_TYPE_STRING, knot2_def_type);
		knot3type = options.getEnum(KNOT3_TYPE_STRING, knot3_def_type);
		knot4type = options.getEnum(KNOT4_TYPE_STRING, knot4_def_type);
		knot5type = options.getEnum(KNOT5_TYPE_STRING, knot5_def_type);

	}

	private void addPaletteKnot(String name, Color col, double point, double width) {
		int palettewidth = 256;
		int pointint = (int) Math.floor((palettewidth / 8.0) * point);
		if (pointint > 255) {
			pointint = 255;
		}
		int widthint = (int) Math.floor((palettewidth / 8.0) * width);
		int start = pointint - widthint;
		if (start < 0) {
			start = 0;
		}
		palette.addKnot(name, col, start, pointint);
	}

	private void updatePalettes() {
		palette.setBase(Color.decode("0x000000"), Color.decode("0xffffff"));
		addPaletteKnots();
		service.paletteChanged();
	}

	private void addPaletteKnots() {
		EntropyRecord rec = knot1type.getRecord();
		if (rec != null) {
			addPaletteKnot(rec.name, knot1color, rec.center, rec.width);
		}
		rec = knot2type.getRecord();
		if (rec != null) {
			addPaletteKnot(rec.name, knot2color, rec.center, rec.width);
		}
		rec = knot3type.getRecord();
		if (rec != null) {
			addPaletteKnot(rec.name, knot3color, rec.center, rec.width);
		}
		rec = knot4type.getRecord();
		if (rec != null) {
			addPaletteKnot(rec.name, knot4color, rec.center, rec.width);
		}
		rec = knot5type.getRecord();
		if (rec != null) {
			addPaletteKnot(rec.name, knot5color, rec.center, rec.width);
		}
	}

	/**
	 * Returns the current chunk size option value.
	 * @return  the current chunk size option value.
	 */
	public int getChunkSize() {
		return chunksize.getChunkSize();
	}

	/**
	 * Returns the palette computed after reading the options.
	 * @return the color palette for the {@link EntropyOverviewColorService}
	 */
	public Palette getPalette() {
		return palette;
	}

}
