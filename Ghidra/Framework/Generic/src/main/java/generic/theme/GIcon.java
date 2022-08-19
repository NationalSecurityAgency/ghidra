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
package generic.theme;

import java.awt.Component;
import java.awt.Graphics;
import java.net.URL;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import ghidra.util.datastruct.WeakStore;
import resources.ResourceManager;
import resources.icons.UrlImageIcon;

/**
 * An {@link Icon} whose value is dynamically determined by looking up its id into a global
 * icon table that is determined by the active {@link GTheme}.
 * <P> The idea is for developers to
 * not use specific icons in their code, but to instead use a GIcon with an id that hints at 
 * its use. For example, instead of harding code a label's icon by coding 
 * "lable.setIcon(ResourceManager.loadImage("images/refresh.png", you would do something like 
 * label.setIcon(new GIcon("icon.refresh"). Then in a "[module name].theme.properties" file 
 * (located in the module's data directory), you would set the default value by adding this
 * line "icon.refresh = images/refresh.png".
 */
public class GIcon implements Icon {
	private static WeakStore<GIcon> inUseIcons = new WeakStore<>();

	private String id;
	private Icon delegate;

	/**
	 * Static method for notifying all the existing GIcon that icons have changed and they
	 * should reload their cached indirect icon. 
	 */
	public static void refreshAll() {
		for (GIcon gIcon : inUseIcons.getValues()) {
			gIcon.refresh();
		}
	}

	/**
	 * Construct a GIcon with an id that will be used to look up the current icon associated with
	 * that id, which can be changed at runtime.
	 * @param id the id used to lookup the current value for this color
	 */
	public GIcon(String id) {
		this(id, true);
	}

	/**
	 * Construct a GIcon with an id that will be used to look up the current icon associated with
	 * that id, which can be changed at runtime.
	 * @param id the id used to lookup the current value for this icon
	 * @param validate if true, an error will be generated if the id can't be resolved to a icon
	 * at this time
	 */
	public GIcon(String id, boolean validate) {
		this.id = id;
		delegate = Gui.getRawIcon(id, validate);
		inUseIcons.add(this);
	}

	/**
	 * Returns the id for this GIcon.
	 * @return the id for this GIcon.
	 */
	public String getId() {
		return id;
	}

	/**
	 * Returns the url used to load the icon delegate of this class.  If the delegate icon was not 
	 * loaded from a url, then null will be returned.
	 * @return the icon or null
	 */
	public URL getUrl() {
		if (delegate instanceof UrlImageIcon) {
			return ((UrlImageIcon) delegate).getUrl();
		}
		return null;
	}

	/**
	 * Returns the image for this icon.  
	 * @return the image
	 */
	public ImageIcon getImageIcon() {
		return ResourceManager.getImageIcon(delegate);
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

	/**
	 * Reloads the delegate.
	 */
	public void refresh() {
		Icon icon = Gui.getRawIcon(id, false);
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
