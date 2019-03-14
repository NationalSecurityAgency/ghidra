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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Hashtable;
import java.util.Locale;

import javax.help.*;
import javax.help.Map.ID;
import javax.help.event.HelpModelEvent;
import javax.help.plaf.HelpNavigatorUI;
import javax.help.plaf.basic.BasicTOCCellRenderer;
import javax.help.plaf.basic.BasicTOCNavigatorUI;
import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * A custom Table of Contents view that we specify in our JavaHelp xml documents.  This view 
 * lets us install custom renderers and custom tree items for use by those renderers.  These
 * renderers let us display custom text defined by the TOC_Source.xml files.  We also add some
 * utility like: tooltips in development mode, node selection when pressing F1.
 */
public class CustomTOCView extends TOCView {

	private CustomTOCNavigatorUI ui;

	private boolean isSelectingNodeInternally;

	// Hashtable
	public CustomTOCView(HelpSet hs, String name, String label,
			@SuppressWarnings("rawtypes") Hashtable params) {
		this(hs, name, label, hs.getLocale(), params);
	}

	// Hashtable
	public CustomTOCView(HelpSet hs, String name, String label, Locale locale,
			@SuppressWarnings("rawtypes") Hashtable params) {
		super(hs, name, label, locale, params);
	}

	@Override
	// overrode this method to install our custom UI, which lets us use our custom renderer
	public Component createNavigator(HelpModel model) {
		JHelpTOCNavigator helpTOCNavigator = new JHelpTOCNavigator(this, model) {
			@Override
			public void setUI(HelpNavigatorUI newUI) {
				CustomTOCView.this.ui = new CustomTOCNavigatorUI(this);
				super.setUI(CustomTOCView.this.ui);
			}
		};

		return helpTOCNavigator;
	}

	public HelpModel getHelpModel() {
		return ui.getHelpModel();
	}

	@Override
	// overrode this method to install our custom factory
	public DefaultMutableTreeNode getDataAsTree() {

		DefaultMutableTreeNode superNode = super.getDataAsTree();
		if (superNode.getChildCount() == 0) {
			return superNode; // something is not initialized
		}

		@SuppressWarnings("rawtypes")
		Hashtable viewParameters = getParameters();
		String TOCData = (String) viewParameters.get("data");
		HelpSet helpSet = getHelpSet();
		URL helpSetURL = helpSet.getHelpSetURL();
		URL url;
		try {
			url = new URL(helpSetURL, TOCData);
		}
		catch (Exception ex) {
			throw new Error("Unable to create tree for view data: " + ex);
		}

		return parse(url, helpSet, helpSet.getLocale(), new CustomDefaultTOCFactory(), this);
	}

	/**
	 * Our custom factory that knows how to look for extra XML attributes and how to 
	 * create our custom tree items
	 */
	public static class CustomDefaultTOCFactory extends DefaultTOCFactory {
		@Override
		public TreeItem createItem(String tagName, @SuppressWarnings("rawtypes") Hashtable atts,
				HelpSet hs, Locale locale) {

			try {
				return doCreateItem(tagName, atts, hs, locale);
			}
			catch (Exception e) {
				Msg.error(this, "Unexected error creating a TOC item", e);
				throw new RuntimeException("Unexpected error creating a TOC item", e);
			}
		}

		private TreeItem doCreateItem(String tagName, @SuppressWarnings("rawtypes") Hashtable atts,
				HelpSet hs, Locale locale) {
			TreeItem item = super.createItem(tagName, atts, hs, locale);

			CustomTreeItemDecorator newItem = new CustomTreeItemDecorator((TOCItem) item);

			if (atts != null) {
				String displayText = (String) atts.get("display");
				newItem.setDisplayText(displayText);
				String tocID = (String) atts.get("toc_id");
				newItem.setTocID(tocID);
			}
			return newItem;
		}
	}

	/**
	 * Our hook to install our custom cell renderer.
	 */
	class CustomTOCNavigatorUI extends BasicTOCNavigatorUI {
		public CustomTOCNavigatorUI(JHelpTOCNavigator b) {
			super(b);
		}

		@Override
		public void installUI(JComponent c) {
			super.installUI(c);

			tree.setExpandsSelectedPaths(true);
		}

		@Override
		protected void setCellRenderer(NavigatorView view, JTree tree) {
			Map map = view.getHelpSet().getCombinedMap();
			tree.setCellRenderer(new CustomCellRenderer(map, (TOCView) view));
			ToolTipManager.sharedInstance().registerComponent(tree);
		}

		public HelpModel getHelpModel() {
			JHelpNavigator helpNavigator = getHelpNavigator();
			return helpNavigator.getModel();
		}

		// Overridden to change the value used for the 'historyName', which we want to be our
		// display name and not the item's name
		@Override
		public void valueChanged(TreeSelectionEvent e) {
			if (isSelectingNodeInternally) {
				// ignore our own selection events, as this method will get called twice if we don't
				return;
			}

			JHelpNavigator navigator = getHelpNavigator();
			HelpModel helpModel = navigator.getModel();

			TreeItem treeItem = getSelectedItem(e, navigator);
			if (treeItem == null) {
				return; // nothing selected
			}

			TOCItem item = (TOCItem) treeItem;
			ID itemID = item.getID();
			if (itemID == null) {
				Msg.debug(this, "No help ID for " + item);
				return;
			}

			String presentation = item.getPresentation();
			if (presentation != null) {
				return; // don't currently support presentations
			}

			CustomTreeItemDecorator customItem = (CustomTreeItemDecorator) item;
			String customDisplayText = customItem.getDisplayText();
			try {
				helpModel.setCurrentID(itemID, customDisplayText, navigator);
			}
			catch (InvalidHelpSetContextException ex) {
				Msg.error(this, "Exception setting new help item ID", ex);
			}
		}

		private TOCItem getSelectedItem(TreeSelectionEvent e, JHelpNavigator navigator) {
			TreePath newLeadSelectionPath = e.getNewLeadSelectionPath();
			if (newLeadSelectionPath == null) {
				navigator.setSelectedItems(null);
				return null;
			}

			DefaultMutableTreeNode node =
				(DefaultMutableTreeNode) newLeadSelectionPath.getLastPathComponent();
			TOCItem treeItem = (TOCItem) node.getUserObject();
			navigator.setSelectedItems(new TreeItem[] { treeItem });

			return treeItem;
		}

		// Overridden to try to find a parent file for IDs that are based upon anchors within
		// a file
		@Override
		public synchronized void idChanged(HelpModelEvent e) {
			selectNodeForID(e.getURL(), e.getID());
		}

		private void selectNodeForID(URL url, ID ID) {
			if (ID == null) {
				ID = getClosestID(url);
			}

			TreePath path = tree.getSelectionPath();
			if (isAlreadySelected(path, ID)) {
				return;
			}

			DefaultMutableTreeNode node = getNodeForID(topNode, ID);
			if (node != null) {
				isSelectingNodeInternally = true;
				TreePath newPath = new TreePath(node.getPath());
				tree.setSelectionPath(newPath);
				tree.scrollPathToVisible(newPath);
				isSelectingNodeInternally = false;
				return;
			}

			// See if the given ID is based upon a URL with an anchor.  If that is the case, then
			// there may be a node for the parent file of that URL.  In that case, select the
			// parent file.
			if (url == null) {
				clearSelection();
				return;
			}

			String urlString = url.toExternalForm();
			int anchorIndex = urlString.indexOf('#');
			if (anchorIndex < 0) {
				clearSelection();
				return;
			}

			urlString = urlString.substring(0, anchorIndex);
			try {
				URL newURL = new URL(urlString);
				selectNodeForID(newURL, null);
			}
			catch (MalformedURLException e) {
				// shouldn't happen, as we are starting with a valid URL
				Msg.debug(this,
					"Unexpected error create a help URL from an existing URL: " + urlString, e);
			}
		}

		private ID getClosestID(URL url) {
			HelpModel helpModel = toc.getModel();
			HelpSet helpSet = helpModel.getHelpSet();
			Map combinedMap = helpSet.getCombinedMap();
			return combinedMap.getClosestID(url);
		}

		private boolean isAlreadySelected(TreePath path, ID id) {
			if (path == null) {
				return false;
			}

			Object pathComponent = path.getLastPathComponent();
			if (!(pathComponent instanceof DefaultMutableTreeNode)) {
				return false;
			}

			DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) pathComponent;
			TOCItem item = (TOCItem) treeNode.getUserObject();
			if (item == null) {
				return false;
			}

			ID selectedID = item.getID();
			return selectedID != null && selectedID.equals(id);
		}

		private DefaultMutableTreeNode getNodeForID(DefaultMutableTreeNode node, ID ID) {
			if (ID == null) {
				return null;
			}

			if (isNodeID(node, ID)) {
				return node;
			}

			int childCount = node.getChildCount();
			for (int i = 0; i < childCount; i++) {
				DefaultMutableTreeNode matchingNode =
					getNodeForID((DefaultMutableTreeNode) node.getChildAt(i), ID);
				if (matchingNode != null) {
					return matchingNode;
				}
			}

			return null;
		}

		private boolean isNodeID(DefaultMutableTreeNode node, ID ID) {
			Object userObject = node.getUserObject();
			if (!(userObject instanceof TOCItem)) {
				return false;
			}

			TOCItem item = (TOCItem) userObject;
			ID nodeID = item.getID();
			if (nodeID == null) {
				return false;
			}

			return nodeID.equals(ID);
		}

		private void clearSelection() {
			isSelectingNodeInternally = true;
			tree.clearSelection();
			isSelectingNodeInternally = false;
		}
	}

	static class CustomCellRenderer extends BasicTOCCellRenderer {

		public CustomCellRenderer(Map map, TOCView view) {
			super(map, view);
		}

		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel,
				boolean expanded, boolean leaf, int row, boolean isFocused) {

			CustomCellRenderer renderer =
				(CustomCellRenderer) super.getTreeCellRendererComponent(tree, value, sel, expanded,
					leaf, row, isFocused);

			TOCItem item = (TOCItem) ((DefaultMutableTreeNode) value).getUserObject();
			if (item == null) {
				return renderer;
			}

			CustomTreeItemDecorator customItem = (CustomTreeItemDecorator) item;
			renderer.setText(customItem.getDisplayText());

			if (!SystemUtilities.isInDevelopmentMode()) {
				return renderer;
			}

			URL url = customItem.getURL();
			if (url != null) {
				renderer.setToolTipText(url.toExternalForm());
				return renderer;
			}

			ID id = customItem.getID();
			if (id != null) {
				renderer.setToolTipText("Missing Help - " + id.id + " in '" + id.hs + "' help set");
				return renderer;
			}

			// this can happen if there is no 'target' attribute in the TOC
			// (see TOCView.createItem())
			return renderer;
		}
	}

	/**
	 * A custom tree item that allows us to store and retrieve custom attributes that we parsed
	 * from the TOC xml document.
	 */
	public static class CustomTreeItemDecorator extends javax.help.TOCItem {

		private final TOCItem wrappedItem;
		private String displayText;
		private String tocID;
		private URL cachedURL;

		public CustomTreeItemDecorator(javax.help.TOCItem wrappedItem) {
			super(wrappedItem.getID(), wrappedItem.getImageID(), wrappedItem.getHelpSet(),
				wrappedItem.getLocale());
			this.wrappedItem = wrappedItem;
		}

		void setDisplayText(String text) {
			this.displayText = text;
		}

		public String getDisplayText() {
			return displayText;
		}

		void setTocID(String tocID) {
			this.tocID = tocID;
		}

		public String getTocID() {
			return tocID;
		}

		@Override
		public boolean equals(Object obj) {
			return wrappedItem.equals(obj);
		}

		@Override
		public int getExpansionType() {
			return wrappedItem.getExpansionType();
		}

		@Override
		public HelpSet getHelpSet() {
			return wrappedItem.getHelpSet();
		}

		@Override
		public ID getID() {
			return wrappedItem.getID();
		}

		@Override
		public ID getImageID() {
			return wrappedItem.getImageID();
		}

		@Override
		public Locale getLocale() {
			return wrappedItem.getLocale();
		}

		@Override
		public String getMergeType() {
			return wrappedItem.getMergeType();
		}

		@Override
		public String getName() {
			return wrappedItem.getName();
		}

		@Override
		public String getPresentation() {
			return wrappedItem.getPresentation();
		}

		@Override
		public String getPresentationName() {
			return wrappedItem.getPresentationName();
		}

		@Override
		public URL getURL() {
			if (cachedURL == null) {
				cachedURL = wrappedItem.getURL();
			}
			return cachedURL;
		}

		@Override
		public int hashCode() {
			return wrappedItem.hashCode();
		}

		@Override
		public void setExpansionType(int type) {
			wrappedItem.setExpansionType(type);
		}

		@Override
		public void setHelpSet(HelpSet hs) {
			wrappedItem.setHelpSet(hs);
		}

		@Override
		public void setID(ID id) {
			wrappedItem.setID(id);
		}

		@Override
		public void setMergeType(String mergeType) {
			wrappedItem.setMergeType(mergeType);
		}

		@Override
		public void setName(String name) {
			wrappedItem.setName(name);
		}

		@Override
		public void setPresentation(String presentation) {
			wrappedItem.setPresentation(presentation);
		}

		@Override
		public void setPresentationName(String presentationName) {
			wrappedItem.setPresentationName(presentationName);
		}

		@Override
		public String toString() {
			return displayText;
		}
	}
}
