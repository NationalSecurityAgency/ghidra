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
package docking.theme.gui;

import java.awt.Component;
import java.awt.Graphics;

import javax.swing.Icon;

import resources.ResourceManager;

public class ProtectedIcon implements Icon {
	Icon bomb = ResourceManager.getDefaultIcon();
	Icon delegate;
	boolean isError = false;

	public ProtectedIcon(Icon delegate) {
		this.delegate = delegate;
	}

	public boolean hasError() {
		return isError;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		try {
			delegate.paintIcon(c, g, x, y);
		}
		catch (Exception e) {
			bomb.paintIcon(c, g, x, y);
		}
	}

	@Override
	public int getIconWidth() {
		return delegate.getIconWidth();
	}

	@Override
	public int getIconHeight() {
		return delegate.getIconHeight();
	}
}
