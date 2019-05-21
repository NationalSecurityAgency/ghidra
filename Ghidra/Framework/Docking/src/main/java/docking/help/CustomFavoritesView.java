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
package docking.help;

import java.awt.Component;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.beans.PropertyChangeListener;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Hashtable;
import java.util.Locale;

import javax.help.*;
import javax.help.Map.ID;
import javax.help.event.HelpModelEvent;
import javax.help.plaf.HelpNavigatorUI;
import javax.help.plaf.basic.BasicFavoritesCellRenderer;
import javax.help.plaf.basic.BasicFavoritesNavigatorUI;
import javax.swing.JComponent;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;

import ghidra.util.Msg;

/**
 * This class allows us to change the renderer of the favorites tree. 
 */
public class CustomFavoritesView extends FavoritesView {

	public CustomFavoritesView(HelpSet hs, String name, String label,
			@SuppressWarnings("rawtypes") Hashtable params) {
		this(hs, name, label, hs.getLocale(), params);
	}

	public CustomFavoritesView(HelpSet hs, String name, String label, Locale locale,
			@SuppressWarnings("rawtypes") Hashtable params) {
		super(hs, name, label, locale, params);
	}

	@Override
	public Component createNavigator(HelpModel model) {
		return new CustomHelpFavoritesNavigator(this, model);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	class CustomHelpFavoritesNavigator extends JHelpFavoritesNavigator {

		CustomHelpFavoritesNavigator(NavigatorView view, HelpModel model) {
			super(view, model);
		}

		@Override
		public void setUI(HelpNavigatorUI ui) {
			super.setUI(new CustomFavoritesNavigatorUI(this));
		}
	}

	class CustomFavoritesNavigatorUI extends BasicFavoritesNavigatorUI {

		private PropertyChangeListener titleListener;

		CustomFavoritesNavigatorUI(JHelpFavoritesNavigator b) {
			super(b);
		}

		@Override
		public void installUI(JComponent c) {
			super.installUI(c);

			tree.addKeyListener(new KeyAdapter() {
				@Override
				public void keyReleased(java.awt.event.KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_DELETE ||
						e.getKeyCode() == KeyEvent.VK_BACK_SPACE) {

						removeAction.actionPerformed(null);
					}
				}
			});

			// Note: add a listener to fix the bug described in 'idChanged()' below
			HelpModel model = favorites.getModel();
			titleListener = e -> {

				if (lastIdEvent == null) {
					return;
				}

				currentTitle = (String) e.getNewValue();
				if (currentTitle == null) {
					return;
				}

				String lastTitle = lastIdEvent.getHistoryName();
				if (!currentTitle.equals(lastTitle)) {
					resendNewEventWithFixedTitle(lastIdEvent, currentTitle);
				}
			};

			model.addPropertyChangeListener(titleListener);
		}

		@Override
		public void uninstallUI(JComponent c) {

			HelpModel model = favorites.getModel();
			if (model != null) {
				model.removePropertyChangeListener(titleListener);
			}

			super.uninstallUI(c);
		}

		private void resendNewEventWithFixedTitle(HelpModelEvent originalEvent, String title) {

			HelpModelEvent e = originalEvent;
			HelpModelEvent newEvent =
				new HelpModelEvent(e.getSource(), e.getID(), e.getURL(), title, favorites);
			idChanged(newEvent);
		}

		private HelpModelEvent lastIdEvent;
		private String currentTitle;

		@Override
		protected void setCellRenderer(NavigatorView view, JTree tree) {
			tree.setCellRenderer(new CustomFavoritesCellRenderer(favorites.getModel()));
		}

		@Override
		public void idChanged(HelpModelEvent e) {

			//
			// Overridden to track the change events.  We need this to fix a bug where our
			// parent class will get the wrong title of the page being loaded *when the user
			// has navigated via a hyperlink*.  The result of using the wrong title 
			// manifests itself when the user makes a 'favorite' item--the title will not 
			// match the 'favorite'd page.
			//

			// this is how the super class stores off it's 'contentTitle' variable
			lastIdEvent = e;
			super.idChanged(e);
		}
	}

	class CustomFavoritesCellRenderer extends BasicFavoritesCellRenderer {

		private final HelpModel helpModel;

		public CustomFavoritesCellRenderer(HelpModel helpModel) {
			this.helpModel = helpModel;
		}

		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel,
				boolean expanded, boolean leaf, int row, boolean isFocused) {

			CustomFavoritesCellRenderer renderer =
				(CustomFavoritesCellRenderer) super.getTreeCellRendererComponent(tree, value, sel,
					expanded, leaf, row, isFocused);

			Object o = ((DefaultMutableTreeNode) value).getUserObject();
			FavoritesItem item = (FavoritesItem) o;
			if (item == null) {
				return renderer;
			}

			HelpSet helpSet = helpModel.getHelpSet();
			Map combinedMap = helpSet.getCombinedMap();
			URL URL = getURL(item, helpSet, combinedMap);
			if (URL == null) {
				// should only happen if the user has old favorites; trust the old name
				return renderer;
			}

			String text = URL.getFile();
			int index = text.lastIndexOf('/');
			if (index != -1) {
				// we want just the filename
				text = text.substring(index + 1);
			}

			String ref = URL.getRef();
			if (ref != null) {
				text += "#" + ref;
			}

			renderer.setText(item.getName() + " - " + text);

			return renderer;
		}

		private URL getURL(FavoritesItem item, HelpSet helpSet, Map combinedMap) {
			String target = item.getTarget();
			if (target == null) {
				// use the URL of the item
				return item.getURL();
			}

			ID newID = null;
			try {
				newID = ID.create(target, helpSet);
			}
			catch (BadIDException e) {
				Msg.debug(this, "Invalid help ID; Mabye bad favorite bookmark?: " + target);
				return null;
			}

			try {
				return combinedMap.getURLFromID(newID);
			}
			catch (MalformedURLException e) {
				//shouldn't happen
				Msg.error(this, "Unexpected Exception", e);
			}
			return null;
		}
	}
}
