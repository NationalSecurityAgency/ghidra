/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.util;

import ghidra.feature.vt.gui.filters.AncillaryFilterDialogComponentProvider;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import resources.ResourceManager;

public class FilterIconFlashTimer<T> extends Timer implements ActionListener {

	private static final Icon EMPTY_ICON = ResourceManager.loadImage("images/EmptyIcon16.gif");
	private static final long MINIMUM_TIME_BETWEEN_FLASHES = 20000;
	private static final int MAX_FLASH_COUNT = 10;

	private int flashCount = 0;
	private long lastFlashTime;

	private final JButton filterButton;
	private final AncillaryFilterDialogComponentProvider<T> filterDialog;
	private final Icon baseIcon;
	private final Icon filteredIcon;

	public FilterIconFlashTimer(Icon baseIcon, Icon filteredIcon,
			AncillaryFilterDialogComponentProvider<T> filterDialog, JButton filterButton) {
		super(250, null);
		this.baseIcon = baseIcon;
		this.filteredIcon = filteredIcon;
		this.filterDialog = filterDialog;
		this.filterButton = filterButton;
		addActionListener(this);
	}

	public void actionPerformed(ActionEvent event) {
		if (!filterDialog.isFiltered()) {
			stop();
			return; // no filter applied
		}

		if (flashCount < MAX_FLASH_COUNT) {
			changeIcon();
			flashCount++;
		}
		else {
			stop();
			stallAnimation();
		}
	}

	@Override
	public void restart() {
		if ((System.currentTimeMillis() - lastFlashTime) < MINIMUM_TIME_BETWEEN_FLASHES) {
			return;
		}

		flashCount = 0;
		super.restart();
	}

	@Override
	public void stop() {
		super.stop();
		restoreBaseIcon();
		flashCount = 0;
	}

	private void changeIcon() {
		Icon currentIcon = filterButton.getIcon();
		if (currentIcon == filteredIcon) {
			filterButton.setIcon(EMPTY_ICON);
		}
		else {
			filterButton.setIcon(filteredIcon);
		}
	}

	private void restoreBaseIcon() {
		if (filterDialog.isFiltered()) {
			filterButton.setIcon(filteredIcon);
		}
		else {
			filterButton.setIcon(baseIcon);
		}
	}

	private void stallAnimation() {
		// this prevents focus from flashing for MINIMUM_TIME_BETWEEN_FLASHES
		lastFlashTime = System.currentTimeMillis();
	}
}
