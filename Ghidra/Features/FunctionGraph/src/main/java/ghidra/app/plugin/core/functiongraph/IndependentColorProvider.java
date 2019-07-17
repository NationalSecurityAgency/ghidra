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
package ghidra.app.plugin.core.functiongraph;

import java.awt.Color;
import java.awt.Component;
import java.util.*;

import org.jdom.Element;

import docking.ComponentPlaceholder;
import docking.DockingWindowManager;
import docking.options.editor.GhidraColorChooser;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphVertexAttributes;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;

class IndependentColorProvider implements FGColorProvider {

	private static final String VERTEX_COLORS = "VERTEX_COLORS";

	private RecentColorCache recentColorCache = new RecentColorCache();

	private final PluginTool tool;

	IndependentColorProvider(PluginTool tool) {
		this.tool = tool;
	}

	@Override
	public boolean isUsingCustomColors() {
		return true;
	}

	@Override
	public Color getColorFromUser(Color startColor) {
		GhidraColorChooser chooser = new GhidraColorChooser(startColor);
		chooser.setTitle("Please Select Background Color");
		List<Color> recentColors = recentColorCache.getMRUColorList();
		chooser.setColorHistory(recentColors);
		Color newColor = chooser.showDialog(getActiveComponent());
		if (newColor != null && !newColor.equals(startColor)) {
			recentColorCache.addColor(newColor);
			tool.setConfigChanged(true);
		}
		return newColor;
	}

	private Component getActiveComponent() {
		DockingWindowManager manager = DockingWindowManager.getActiveInstance();
		ComponentPlaceholder placeholder = manager.getFocusedComponent();
		if (placeholder != null) { // may be null if the app loses focus
			return placeholder.getComponent();
		}
		return manager.getActiveComponent();
	}

	@Override
	public void setVertexColor(FGVertex vertex, Color newColor) {
		vertex.setBackgroundColor(newColor);
	}

	@Override
	public void clearVertexColor(FGVertex vertex) {
		vertex.clearColor();
	}

	@Override
	public Color getMostRecentColor() {
		return recentColorCache.getMostRecentColor();
	}

	@Override
	public List<Color> getRecentColors() {
		return recentColorCache.getMRUColorList();
	}

	@Override
	public void savePluginColors(SaveState saveState) {
		// store off global colors for vertices
		Element colorsElement = new Element(VERTEX_COLORS);
		for (Color color : recentColorCache) {
			Element element = new Element("COLOR");
			element.setAttribute("RGB", Integer.toString(color.getRGB()));
			colorsElement.addContent(element);
		}
		saveState.putXmlElement(VERTEX_COLORS, colorsElement);
	}

	@SuppressWarnings("unchecked")
	// casting the getChildren() of element
	@Override
	public void loadPluginColor(SaveState saveState) {
		// globally used vertex colors        
		Element xmlElement = saveState.getXmlElement(VERTEX_COLORS);
		if (xmlElement != null) {
			List<Element> colorElements = xmlElement.getChildren("COLOR");
			for (Element element : colorElements) {
				String rgbString = element.getAttributeValue("RGB");
				int rgb = Integer.parseInt(rgbString);
				recentColorCache.addColor(new Color(rgb, true));
			}
		}
	}

	@Override
	public void saveVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings) {
		Color userDefinedColor = vertex.getUserDefinedColor();
		if (userDefinedColor != null) {
			settings.putVertexColor(vertex.getVertexAddress(), userDefinedColor);
		}
	}

	@Override
	public void loadVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings) {
		Color savedColor = settings.getVertexColor(vertex.getVertexAddress());
		if (savedColor != null) {
			vertex.restoreColor(savedColor);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class RecentColorCache extends LinkedHashMap<Color, Color> implements Iterable<Color> {
		private static final int MAX_SIZE = 10;
		private Color mostRecentColor = Color.blue;

		RecentColorCache() {
			super(16, 0.75f, true);
		}

		@Override
		protected boolean removeEldestEntry(Map.Entry<Color, Color> eldest) {
			return size() > MAX_SIZE;
		}

		@Override
		public Iterator<Color> iterator() {
			return keySet().iterator();
		}

		public void addColor(Color color) {
			put(color, color);
			mostRecentColor = color;
		}

		public List<Color> getMRUColorList() {
			List<Color> list = new ArrayList<>(this.keySet());
			Collections.reverse(list); // we are in LRU order, so reverse it
			return list;
		}

		public Color getMostRecentColor() {
			return mostRecentColor;
		}
	}

}
