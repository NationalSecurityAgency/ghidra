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
package ghidra.app.plugin.core.debug.gui.timeoverview.timetype;

import java.awt.Color;
import java.math.BigInteger;
import java.util.*;

import org.apache.commons.lang3.tuple.Pair;

import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import docking.action.builder.ActionBuilder;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.core.debug.gui.timeoverview.*;
import ghidra.app.plugin.core.overview.OverviewColorLegendDialog;
import ghidra.app.plugin.core.overview.OverviewColorPlugin;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.util.*;

public class TimeTypeOverviewColorService implements TimeOverviewColorService {
	private static final String OPTIONS_NAME = "Time Overview";
	private static final Color DEFAULT_UNDEFINED_COLOR = Color.LIGHT_GRAY;
	private static final Color DEFAULT_UNINITIALIZED_COLOR = Color.GRAY;

	Map<TimeType, Color> colorMap = new HashMap<>();
	Color undefinedColor = DEFAULT_UNDEFINED_COLOR;
	Color uninitializedColor = DEFAULT_UNINITIALIZED_COLOR;

	private Trace trace;
	protected TimeOverviewColorComponent overviewComponent;
	private PluginTool tool;
	private DialogComponentProvider legendDialog;
	private TimeTypeOverviewLegendPanel legendPanel;
	private TimeOverviewColorPlugin plugin;

	protected Map<Integer,Long> indexToSnap = new HashMap<>();
	protected Map<Long,Integer> snapToIndex = new HashMap<>();
	protected Lifespan bounds;

	@Override
	public String getName() {
		return "Trace Overview";
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("DebuggerTimeOverviewPlugin", "plugin");
	}

	@Override
	public Color getColor(Long snap) {
		Set<Pair<TimeType, String>> types = plugin.getTypes(snap);
		Color c = Colors.BACKGROUND;
		for (Pair<TimeType, String> pair : types) {
			c = ColorUtils.addColors(c, pair.getLeft().getDefaultColor());
		}
		return c;
	}

	@Override
	public String getToolTipText(Long snap) {
		// TODO:  Right now, there's an inconsistency in how time is rendered
		//   the Time Table uses decimal; the Model Tree, Memview, and Overview
		//   use hex
		if (snap == null) {
			return "";
		}
		Set<Pair<TimeType, String>> types = plugin.getTypes(snap);
		StringBuffer buffer = new StringBuffer();
		buffer.append("<b>");
		buffer.append(HTMLUtilities.escapeHTML(getName()));
		buffer.append(" (");
		buffer.append(Long.toHexString(snap));
		buffer.append(")");
		buffer.append("</b>\n");
		for (Pair<TimeType, String> pair : types) {
			TimeType tt = pair.getLeft();
			String key = pair.getRight();
			buffer.append(tt.getDescription() + " : " + key + "\n");
		}
		return HTMLUtilities.toWrappedHTML(buffer.toString(), 0);
	}

	@Override
	public List<DockingActionIf> getActions() {
		List<DockingActionIf> actions = new ArrayList<>();
		actions.add(new ActionBuilder("Show Legend", getName())
				.popupMenuPath("Show Legend")
				.description("Show types and associated colors")
				.helpLocation(getHelpLocation())
				.enabledWhen(c -> c.getContextObject() == overviewComponent)
				.onAction(c -> tool.showDialog(getLegendDialog()))
				.build());

		return actions;
	}

	@Override
	public void setTrace(Trace trace) {
		this.trace = trace;
	}

	@Override
	public void initialize(PluginTool pluginTool) {
		this.tool = pluginTool;
	}

	@Override
	public void setOverviewComponent(TimeOverviewColorComponent component) {
		this.overviewComponent = component;
	}

	/**
	 * Returns the color associated with the given {@link TimeType}
	 *
	 * @param timeType the span type for which to get a color.
	 * @return the color associated with the given {@link TimeType}
	 */
	public Color getColor(TimeType timeType) {
		Color color = colorMap.get(timeType);
		if (color == null) {
			colorMap.put(timeType, timeType.getDefaultColor());
		}
		return color;
	}

	/**
	 * Sets the color to be associated with a given {@link TimeType}
	 *
	 * @param type the LifespanType for which to assign the color.
	 * @param newColor the new color for the given {@link TimeType}
	 */
	public void setColor(TimeType type, Color newColor) {
		ToolOptions options = tool.getOptions(OPTIONS_NAME);
		options.setColor(type.getDescription(), newColor);
	}

	private DialogComponentProvider getLegendDialog() {
		if (legendDialog == null) {
			legendPanel = new TimeTypeOverviewLegendPanel(this);

			legendDialog =
				new OverviewColorLegendDialog("Overview Legend", legendPanel, getHelpLocation());
		}
		return legendDialog;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public void setPlugin(TimeOverviewColorPlugin plugin) {
		this.plugin = plugin;
	}

	@Override
	public Long getSnap(int pixelIndex) {
		BigInteger bigHeight = BigInteger.valueOf(overviewComponent.getOverviewPixelCount());
		BigInteger bigPixelIndex = BigInteger.valueOf(pixelIndex);
		
		BigInteger span = BigInteger.valueOf(indexToSnap.size());
		BigInteger offset = span.multiply(bigPixelIndex).divide(bigHeight);
		return indexToSnap.get(offset.intValue());
	}

	@Override
	public void setIndices(TreeSet<Long> set) {
		snapToIndex = new HashMap<>();
		indexToSnap = new HashMap<>();
		int index = 0;
		Iterator<Long> iterator = set.iterator();
		while (iterator.hasNext()) {
			Long snap = iterator.next();
			snapToIndex.put(snap, index);
			indexToSnap.put(index, snap);
			index++;
		}
	}

	@Override
	public Lifespan getBounds() {
		return bounds;
	}

	@Override
	public void setBounds(Lifespan bounds) {
		this.bounds = bounds;
	}

}
