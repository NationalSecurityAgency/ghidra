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
package ghidra.feature.vt.gui.provider.relatedMatches;

import java.awt.*;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import docking.widgets.label.GIconLabel;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.util.table.GhidraTableCellRenderer;
import resources.ResourceManager;

public class RelatedMatchRenderer extends GhidraTableCellRenderer {
	static Map<VTRelatedMatchCorrelationType, JLabel> sourceMap;
	static Map<VTRelatedMatchCorrelationType, JLabel> destinationMap;
	static Map<VTAssociationStatus, JLabel> statusMap;

	static final Icon TARGET_ICON = ResourceManager.loadImage("images/user-online.png");
	static final Icon CALLER_ICON = ResourceManager.loadImage("images/go-down.png");
	static final Icon CALLEE_ICON = ResourceManager.loadImage("images/go-next.png");
	static final Icon UNRELATED_ICON = ResourceManager.loadImage("images/user-busy.png");

	static final Icon ACCEPTED_ICON = ResourceManager.loadImage("images/accept.png");
	static final Icon AVAILABLE_ICON = ResourceManager.loadImage("images/media-playback-stop.png");
	static final Icon LOCKED_OUT_ICON = ResourceManager.loadImage("images/edit-delete.png");

	private JPanel relatedMatchColumnComponent;
	private GridLayout layout;

	public RelatedMatchRenderer() {
		initialize();
		relatedMatchColumnComponent = new JPanel();
		layout = new GridLayout(1, 3);
		relatedMatchColumnComponent.setLayout(layout);
	}

	private static void initialize() {
		if (sourceMap == null) {
			sourceMap = new HashMap<>();
			sourceMap.put(VTRelatedMatchCorrelationType.TARGET, new GIconLabel(TARGET_ICON));
			sourceMap.put(VTRelatedMatchCorrelationType.CALLER, new GIconLabel(CALLER_ICON));
			sourceMap.put(VTRelatedMatchCorrelationType.CALLEE, new GIconLabel(CALLEE_ICON));
			sourceMap.put(VTRelatedMatchCorrelationType.UNRELATED, new GIconLabel(UNRELATED_ICON));

			destinationMap = new HashMap<>();
			destinationMap.put(VTRelatedMatchCorrelationType.TARGET, new GIconLabel(TARGET_ICON));
			destinationMap.put(VTRelatedMatchCorrelationType.CALLER, new GIconLabel(CALLER_ICON));
			destinationMap.put(VTRelatedMatchCorrelationType.CALLEE, new GIconLabel(CALLEE_ICON));
			destinationMap.put(VTRelatedMatchCorrelationType.UNRELATED,
				new GIconLabel(UNRELATED_ICON));

			statusMap = new HashMap<>();
			statusMap.put(VTAssociationStatus.ACCEPTED, new GIconLabel(ACCEPTED_ICON));
			statusMap.put(VTAssociationStatus.AVAILABLE, new GIconLabel(AVAILABLE_ICON));
			statusMap.put(VTAssociationStatus.BLOCKED, new GIconLabel(LOCKED_OUT_ICON));
		}
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Object value = data.getValue();

		if (value instanceof VTRelatedMatchType) {
			VTRelatedMatchType relatedMatchType = (VTRelatedMatchType) value;
			relatedMatchColumnComponent.removeAll();
			relatedMatchColumnComponent.add(sourceMap.get(relatedMatchType.getSourceType()));
			relatedMatchColumnComponent.add(
				destinationMap.get(relatedMatchType.getDestinationType()));
			relatedMatchColumnComponent.add(statusMap.get(relatedMatchType.getAssociationStatus()));
			Color bgColor = findBackgroundColor(relatedMatchType);
			if (bgColor != null) {
				relatedMatchColumnComponent.setBackground(bgColor);
			}
			return relatedMatchColumnComponent;
		}

		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		renderer.setToolTipText(null);

		return renderer;
	}

	private static final Color GOOD = Color.green;
	private static final Color MEDIUM = Color.yellow;
	private static final Color BAD = Color.red;

	private Color findBackgroundColor(VTRelatedMatchType value) {
		double goodness = value.getGoodness() / 100.0;
		double badness = 1.0 - goodness;
		Color color1 = goodness > 0.5 ? GOOD : MEDIUM;
		Color color2 = goodness > 0.5 ? MEDIUM : BAD;
		double red = color1.getRed() * goodness + color2.getRed() * badness;
		double grn = color1.getGreen() * goodness + color2.getGreen() * badness;
		double blu = color1.getBlue() * goodness + color2.getBlue() * badness;
		return new Color((int) red, (int) grn, (int) blu);
	}
}
