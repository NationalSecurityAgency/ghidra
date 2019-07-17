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
package ghidra.app.plugin.core.codebrowser;

import java.awt.Color;
import java.math.BigInteger;

import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;

/**
 * Class for blending two {@link ListingBackgroundColorModel}s.  If neither model has a color
 * different from its default, then the primary's color is returned.  If only one model
 * has a color different from its default, that that color is returned.  If they both have
 * colors different, the color returned is a blend of the two colors.
 */

public class LayeredColorModel implements ListingBackgroundColorModel {
	private ListingBackgroundColorModel primaryModel;
	private ListingBackgroundColorModel secondaryModel;

	public LayeredColorModel(ListingBackgroundColorModel primary,
			ListingBackgroundColorModel secondary) {
		this.primaryModel = primary;
		this.secondaryModel = secondary;
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		Color primaryColor = primaryModel.getBackgroundColor(index);
		Color secondaryColor = secondaryModel.getBackgroundColor(index);
		if (primaryColor.equals(primaryModel.getDefaultBackgroundColor())) {
			return secondaryColor;
		}
		if (secondaryColor.equals(secondaryModel.getDefaultBackgroundColor())) {
			return primaryColor;
		}
		return blend(primaryColor, secondaryColor);
	}

	private Color blend(Color primary, Color secondary) {
		int red = (primary.getRed() * 2 + secondary.getRed()) / 3;
		int green = (primary.getGreen() * 2 + secondary.getGreen()) / 3;
		int blue = (primary.getBlue() * 2 + secondary.getBlue()) / 3;
		return new Color(red, green, blue);
	}

	@Override
	public Color getDefaultBackgroundColor() {
		return primaryModel.getDefaultBackgroundColor();
	}

	@Override
	public void setDefaultBackgroundColor(Color c) {
		primaryModel.setDefaultBackgroundColor(c);
		secondaryModel.setDefaultBackgroundColor(c);
	}

	@Override
	public void modelDataChanged(ListingPanel listingPanel) {
		primaryModel.modelDataChanged(listingPanel);
		secondaryModel.modelDataChanged(listingPanel);
	}

}
