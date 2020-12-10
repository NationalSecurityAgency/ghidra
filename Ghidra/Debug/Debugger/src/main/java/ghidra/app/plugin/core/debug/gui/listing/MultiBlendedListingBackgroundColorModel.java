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

import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;

public class MultiBlendedListingBackgroundColorModel implements ListingBackgroundColorModel {
	private final List<ListingBackgroundColorModel> models = new ArrayList<>();

	private final List<Color> toBlend = new ArrayList<>();

	public MultiBlendedListingBackgroundColorModel() {
	}

	public void addModel(ListingBackgroundColorModel m) {
		models.add(m);
	}

	public void removeModel(ListingBackgroundColorModel m) {
		models.remove(m);
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		toBlend.clear();
		for (ListingBackgroundColorModel m : models) {
			Color c = m.getBackgroundColor(index);
			if (c == null) {
				continue;
			}
			if (c.equals(m.getDefaultBackgroundColor())) {
				continue;
			}
			toBlend.add(c);
		}
		int size = toBlend.size();
		if (size == 0) {
			return getDefaultBackgroundColor();
		}
		if (size == 1) {
			return toBlend.get(0);
		}
		return blend();
	}

	protected Color blend() {
		int r = 0;
		int g = 0;
		int b = 0;
		int ta = 0;
		for (Color c : toBlend) {
			int a = c.getAlpha();
			ta += a;
			r += a * c.getRed();
			g += a * c.getGreen();
			b += a * c.getBlue();
		}
		return ta == 0 ? getDefaultBackgroundColor() : new Color(r / ta, g / ta, b / ta);
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
		for (ListingBackgroundColorModel m : models) {
			m.setDefaultBackgroundColor(c);
		}
	}

	@Override
	public void modelDataChanged(ListingPanel listingPanel) {
		for (ListingBackgroundColorModel m : models) {
			m.modelDataChanged(listingPanel);
		}
	}
}
