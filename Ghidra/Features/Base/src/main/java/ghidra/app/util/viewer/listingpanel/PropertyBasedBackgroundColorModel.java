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
package ghidra.app.util.viewer.listingpanel;

import java.awt.Color;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import docking.widgets.fieldpanel.support.BackgroundColorModel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.database.IntRangeMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;

/**
 * Default {@link BackgroundColorModel} for the ListingPanel where the color returned
 * for an index is based on that corresponding address having a color set in the
 * program's database. (You can "paint" colors over address ranges).
 */
public class PropertyBasedBackgroundColorModel
		implements ListingBackgroundColorModel, DomainObjectListener {

	public static final String COLOR_PROPERTY_NAME = "LISTING_COLOR";
	private IntRangeMap colorMap;
	private AddressIndexMap indexMap;
	private Color defaultBackgroundColor = Color.WHITE;
	private Map<Integer, Color> colorCache = new HashMap<>();
	private Program program;
	private boolean enabled = false;

	public PropertyBasedBackgroundColorModel() {
	}

	@Override
	public void modelDataChanged(ListingPanel listingPanel) {
		Program newProgram = listingPanel.getProgram();
		updateListener(newProgram);
		this.program = newProgram;
		this.indexMap = listingPanel.getAddressIndexMap();
		colorMap = program == null ? null : program.getIntRangeMap(COLOR_PROPERTY_NAME);
	}

	private void updateListener(Program newProgram) {
		if (newProgram == program) {
			return;
		}
		if (program != null) {
			program.removeListener(this);
		}
		if (newProgram != null) {
			newProgram.addListener(this);
		}

	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		if (!enabled || colorMap == null) {
			return defaultBackgroundColor;
		}
		Address address = indexMap.getAddress(index);
		Color color = null;
		if (address != null) {
			color = getColor(address);
		}
		if (color == null) {
			color = defaultBackgroundColor;
		}
		return color;
	}

	private Color getColor(Address address) {
		Integer value = colorMap.getValue(address);
		if (value == null) {
			return null;
		}
		Color c = colorCache.get(value);
		if (c == null) {
			c = new Color(value, true);
			colorCache.put(value, c);
		}
		return c;
	}

	@Override
	public Color getDefaultBackgroundColor() {
		return defaultBackgroundColor;
	}

	@Override
	public void setDefaultBackgroundColor(Color c) {
		defaultBackgroundColor = c;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED)) {
			colorMap = program.getIntRangeMap(COLOR_PROPERTY_NAME);

		}

	}

	public void setEnabled(boolean b) {
		enabled = b;
	}
}
