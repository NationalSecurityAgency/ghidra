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
package ghidra.app.util.viewer.util;

import java.util.List;

import docking.widgets.fieldpanel.support.AnchoredLayout;
import ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap;
import ghidra.program.model.address.*;

/**
 * Maps vertical pixel locations to layouts on the currently displayed screen.
 */
public class VerticalPixelAddressMapImpl implements VerticalPixelAddressMap {
	private List<AnchoredLayout> layouts;
	private final AddressIndexMap map;
	private AddressSetView viewedAddresses;

	/**
	 * Constructor.
	 *
	 * @param layouts the set of layouts that are currently visible on the screen
	 * @param map the map containing the addresses by index
	 */
	public VerticalPixelAddressMapImpl(List<AnchoredLayout> layouts, AddressIndexMap map) {
		super();
		this.layouts = layouts;
		this.map = map;
	}

	@Override
	public Address getStartAddress() {
		return map.getAddress(layouts.get(0).getIndex());
	}

	@Override
	public Address getEndAddress() {
		return map.getAddress(layouts.get(layouts.size() - 1).getIndex());
	}

	@Override
	public int getNumLayouts() {
		return layouts.size();
	}

	@Override
	public Address getLayoutAddress(int i) {
		if (i < 0 || i >= layouts.size()) {
			return null;
		}
		return map.getAddress(layouts.get(i).getIndex());
	}

	@Override
	public Address getLayoutEndAddress(int i) {
		if (i < 0 || i >= layouts.size()) {
			return null;
		}

		Address addr = map.getAddress(layouts.get(i).getIndex());
		try {
			return addr.add(layouts.get(i).getIndexSize() - 1);
		}
		catch (AddressOutOfBoundsException e) {
			// TODO we need a better description of when this can happen
			return null;
		}
	}

	@Override
	public int getBeginPosition(int i) {
		if (i < 0 || i >= layouts.size()) {
			return 0;
		}
		return layouts.get(i).getYPos();
	}

	@Override
	public int getEndPosition(int i) {
		if (i < 0 || i >= layouts.size()) {
			return 0;
		}
		return (layouts.get(i).getYPos() + layouts.get(i).getHeight() - 1);
	}

	@Override
	public int getMarkPosition(int i) {
		if (i < 0 || i >= layouts.size()) {
			return 0;
		}
		return getBeginPosition(i) + layouts.get(i).getPrimaryOffset();
	}

	@Override
	public boolean hasPrimaryField(int i) {
		if (i < 0 || i >= layouts.size()) {
			return false;
		}
		return (layouts.get(i).getPrimaryOffset() >= 0);
	}

	@Override
	public int findLayoutAt(int y) {
		for (int i = 0; i < layouts.size(); i++) {
			if (layouts.get(i).contains(y)) {
				return i;
			}
		}
		return -1;
	}

	public int getLayoutIndexSize(int i) {
		return layouts.get(i).getIndexSize();
	}

	@Override
	public AddressSetView getAddressSet() {
		// If there are no visible layouts (no open data to display or listing component height = 0)
		if (layouts.isEmpty()) {
			return new AddressSet();
		}
		if (viewedAddresses == null) {
			viewedAddresses =
				map.getOriginalAddressSet().intersectRange(getStartAddress(), getEndAddress());
		}
		return viewedAddresses;
	}
}
