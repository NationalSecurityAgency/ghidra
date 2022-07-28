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
package docking.theme;

import java.awt.Component;
import java.awt.Graphics;

import javax.swing.Icon;

import resources.ResourceManager;

public class GIcon implements Icon, Refreshable {

	private String id;
	private Icon delegate;

	public GIcon(String id) {
		this.id = id;
		delegate = Gui.getRawIcon(id);
		if (delegate == null) {
			delegate = ResourceManager.getDefaultIcon();
		}
	}

	public String getId() {
		return id;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		delegate.paintIcon(c, g, x, y);
	}

	@Override
	public int getIconWidth() {
		return delegate.getIconWidth();
	}

	@Override
	public int getIconHeight() {
		return delegate.getIconHeight();
	}

	@Override
	public void refresh() {
		Icon icon = Gui.getRawIcon(id);
		if (icon != null) {
			delegate = icon;
		}
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GIcon other = (GIcon) obj;
		return id.equals(other.id);
	}

}
