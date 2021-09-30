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
package ghidra.app.plugin.core.debug.gui.listing;

import java.awt.Color;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.support.BackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.util.ColorUtils.ColorBlender;

public class MultiBlendedListingBackgroundColorModel implements ListingBackgroundColorModel {
	private final List<BackgroundColorModel> models = new ArrayList<>();

	private final ColorBlender blender = new ColorBlender();

	public MultiBlendedListingBackgroundColorModel() {
	}

	public void addModel(BackgroundColorModel m) {
		models.add(m);
	}

	public void removeModel(BackgroundColorModel m) {
		models.remove(m);
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		blender.clear();
		for (BackgroundColorModel m : models) {
			Color c = m.getBackgroundColor(index);
			if (c == null) {
				continue;
			}
			if (c.equals(m.getDefaultBackgroundColor())) {
				continue;
			}
			blender.add(c);
		}
		return blender.getColor(getDefaultBackgroundColor());
	}

	@Override
	public Color getDefaultBackgroundColor() {
		if (models.isEmpty()) {
			return Color.WHITE;
		}
		return models.get(0).getDefaultBackgroundColor();
	}

	@Override
	public void setDefaultBackgroundColor(Color c) {
		for (BackgroundColorModel m : models) {
			m.setDefaultBackgroundColor(c);
		}
	}

	@Override
	public void modelDataChanged(ListingPanel listingPanel) {
		for (BackgroundColorModel m : models) {
			if (!(m instanceof ListingBackgroundColorModel)) {
				continue;
			}
			ListingBackgroundColorModel lm = (ListingBackgroundColorModel) m;
			lm.modelDataChanged(listingPanel);
		}
	}
}
