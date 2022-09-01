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

import generic.theme.GColor;
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
	private static final Color UNINITIALIZED_COLOR =
		new GColor("color.bg.plugin.overview.entropy.uninitialized");
	private static final String OPTIONS_NAME = "Entropy";
	private static final String CHUNKSIZE_STRING = "Chunk size";
	private static final String CHUNKSIZE_DESC_STRING = "Number of bytes per entropy score";
	private static final EntropyChunkSize CHUNKSIZE_DEF = EntropyChunkSize.LARGE;
	private static final String KNOT_COLOR_STRING =
		"Color to use for highlighting a specific range of entropy values";
	private static final String KNOT_TYPE_STRING = "Type of range to highlight";

	private static final String KNOT1_COLOR_STRING = "Range 1 color";
	private static final String KNOT1_TYPE_STRING = "Entropy Range 1";
	private static final Color KNOT1_DEF_COLOR =
		new GColor("color.bg.plugin.overview.entropy.knot.1");
	private static final EntropyKnot KNOT1_DEF_TYPE = EntropyKnot.COMPRESSED;

	private static final String KNOT2_COLOR_STRING = "Range 2 color";
	private static final String KNOT2_TYPE_STRING = "Entropy Range 2";
	private static final Color KNOT2_DEF_COLOR =
		new GColor("color.bg.plugin.overview.entropy.knot.2");
	private static final EntropyKnot KNOT2_DEF_TYPE = EntropyKnot.X86;

	private static final String KNOT3_COLOR_STRING = "Range 3 color";
	private static final String KNOT3_TYPE_STRING = "Entropy Range 3";
	private static final Color KNOT3_DEF_COLOR =
		new GColor("color.bg.plugin.overview.entropy.knot.3");
	private static final EntropyKnot KNOT3_DEF_TYPE = EntropyKnot.ASCII;

	private static final String KNOT4_COLOR_STRING = "Range 4 color";
	private static final String KNOT4_TYPE_STRING = "Entropy Range 4";
	private static final Color KNOT4_DEF_COLOR =
		new GColor("color.bg.plugin.overview.entropy.knot.4");
	private static final EntropyKnot KNOT4_DEF_TYPE = EntropyKnot.UTF16;

	private static final String KNOT5_COLOR_STRING = "Range 5 color";
	private static final String KNOT5_TYPE_STRING = "Entropy Range 5";
	private static final Color KNOT5_DEF_COLOR =
		new GColor("color.bg.plugin.overview.entropy.knot.5");
	private static final EntropyKnot KNOT5_DEF_TYPE = EntropyKnot.NONE;

	private static final Color PALETTE_COLOR_HIGH =
		new GColor("color.bg.plugin.overview.entropy.palette.base.high");
	private static final Color PALETTE_COLOR_LOW =
		new GColor("color.bg.plugin.overview.entropy.palette.base.low");

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
	private Palette palette = new Palette(256, UNINITIALIZED_COLOR);
	private EntropyOverviewColorService service;

	public EntropyOverviewOptionsManager(PluginTool tool, EntropyOverviewColorService service) {
		this.service = service;
		ToolOptions options = tool.getOptions(OPTIONS_NAME);
		HelpLocation help = new HelpLocation(OverviewColorPlugin.HELP_TOPIC, "EntropyOverviewBar");

		options.addOptionsChangeListener(this);
		options.setOptionsHelpLocation(help);

		options.registerOption(CHUNKSIZE_STRING, CHUNKSIZE_DEF, help, CHUNKSIZE_DESC_STRING);
		options.registerOption(KNOT1_COLOR_STRING, KNOT1_DEF_COLOR, help, KNOT_COLOR_STRING);
		options.registerOption(KNOT2_COLOR_STRING, KNOT2_DEF_COLOR, help, KNOT_COLOR_STRING);
		options.registerOption(KNOT3_COLOR_STRING, KNOT3_DEF_COLOR, help, KNOT_COLOR_STRING);
		options.registerOption(KNOT4_COLOR_STRING, KNOT4_DEF_COLOR, help, KNOT_COLOR_STRING);
		options.registerOption(KNOT5_COLOR_STRING, KNOT5_DEF_COLOR, help, KNOT_COLOR_STRING);

		options.registerOption(KNOT1_TYPE_STRING, KNOT1_DEF_TYPE, help, KNOT_TYPE_STRING);
		options.registerOption(KNOT2_TYPE_STRING, KNOT2_DEF_TYPE, help, KNOT_TYPE_STRING);
		options.registerOption(KNOT3_TYPE_STRING, KNOT3_DEF_TYPE, help, KNOT_TYPE_STRING);
		options.registerOption(KNOT4_TYPE_STRING, KNOT4_DEF_TYPE, help, KNOT_TYPE_STRING);
		options.registerOption(KNOT5_TYPE_STRING, KNOT5_DEF_TYPE, help, KNOT_TYPE_STRING);

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
		chunksize = options.getEnum(CHUNKSIZE_STRING, CHUNKSIZE_DEF);

		knot1color = options.getColor(KNOT1_COLOR_STRING, KNOT1_DEF_COLOR);
		knot2color = options.getColor(KNOT2_COLOR_STRING, KNOT2_DEF_COLOR);
		knot3color = options.getColor(KNOT3_COLOR_STRING, KNOT3_DEF_COLOR);
		knot4color = options.getColor(KNOT4_COLOR_STRING, KNOT4_DEF_COLOR);
		knot5color = options.getColor(KNOT5_COLOR_STRING, KNOT5_DEF_COLOR);

		knot1type = options.getEnum(KNOT1_TYPE_STRING, KNOT1_DEF_TYPE);
		knot2type = options.getEnum(KNOT2_TYPE_STRING, KNOT2_DEF_TYPE);
		knot3type = options.getEnum(KNOT3_TYPE_STRING, KNOT3_DEF_TYPE);
		knot4type = options.getEnum(KNOT4_TYPE_STRING, KNOT4_DEF_TYPE);
		knot5type = options.getEnum(KNOT5_TYPE_STRING, KNOT5_DEF_TYPE);

	}

	private void addPaletteKnot(String name, Color color, double point, double width) {
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
		palette.addKnot(name, color, start, pointint);
	}

	private void updatePalettes() {
		palette.setBase(PALETTE_COLOR_LOW, PALETTE_COLOR_HIGH);
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
