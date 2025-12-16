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
import java.awt.Image;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.List;

import javax.help.*;
import javax.help.event.HelpModelEvent;
import javax.help.event.HelpModelListener;
import javax.swing.*;

import docking.framework.ApplicationInformationDisplayFactory;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import help.CustomTOCView;
import help.GHelpBroker;
import resources.Icons;

/**
 * An extension of the {@link GHelpBroker} that allows {@code Docking} classes to be installed.
 * <p>
 * Additions include:
 * <UL> 
 * 	<LI>A find feature</LI>
 *  <LI>A UI navigation aid</LI>
 *  <LI>An action to refresh the current page</LI>
 * </UL>
 */
public class DockingHelpBroker extends GHelpBroker {

	private static final List<Image> ICONS = ApplicationInformationDisplayFactory.getWindowIcons();

	private HelpModelListener helpModelListener = new HelpIDChangedListener();

	private CalloutRequest callout;

	public DockingHelpBroker(HelpSet hs) {
		super(hs);
	}

	@Override
	protected List<Image> getApplicationIcons() {
		return ICONS;
	}

	@Override
	protected HelpModel getCustomHelpModel() {
		//
		// Unusual Code Alert!: We have opened up access to the help system's HelpModel by way
		//                      of our CustomTOCView object that we install elsewhere.  We need
		//                      access to the model because of a bug in the help system
		//                      (SCR 7639).  Unfortunately, the Java Help system does not give us
		//                      access to the model directly, but we have opened up the access from
		//                      one of our overriding components.  The following code is
		//                      digging-out our custom component to get at the model.  An
		//                      alternative approach would be to just use reflection and violate
		//                      security restrictions, but that seemed worse than this solution.
		//

		WindowPresentation windowPresentation = getWindowPresentation();
		HelpSet helpSet = windowPresentation.getHelpSet();
		NavigatorView tocView = helpSet.getNavigatorView("TOC");
		if (!(tocView instanceof CustomTOCView)) {
			// not sure how this could happen
			Msg.debug(this, "The help system is not using the CustomTOCView class!");
			return null;
		}

		CustomTOCView customTOCView = (CustomTOCView) tocView;
		return customTOCView.getHelpModel();
	}

	@Override
	protected void installHelpSearcher(JHelp jHelp, HelpModel helpModel) {
		helpModel.addHelpModelListener(helpModelListener);
		new HelpViewSearcher(jHelp);
	}

	@Override
	protected void showNavigationAid(URL url) {
		prepareToCallout(url);
	}

	@Override
	protected void installActions(JHelp help) {
		JToolBar toolbar = null;
		Component[] components = help.getComponents();
		for (Component c : components) {
			if (c instanceof JToolBar) {
				toolbar = (JToolBar) c;
				break;
			}
		}

		if (toolbar == null) {
			// shouldn't happen
			return;
		}

		// separate the Java help stuff from our actions
		toolbar.addSeparator();

		NavigationAidToggleAction action = new NavigationAidToggleAction();
		toolbar.add(new JButton(action));

		if (SystemUtilities.isInDevelopmentMode()) {

			Action refreshAction = new AbstractAction() {

				{
					putValue(Action.SMALL_ICON, Icons.REFRESH_ICON);
					putValue(Action.SHORT_DESCRIPTION, "Reload the current page");
				}

				@Override
				public void actionPerformed(ActionEvent e) {
					reloadHelpPage(getCurrentURL(), true);
				}
			};
			toolbar.add(new JButton(refreshAction));
		}
	}

	@Override // opened access
	protected void reloadHelpPage(URL url, boolean preserveLocation) {
		super.reloadHelpPage(url, preserveLocation);
	}

//=================================================================================================
// Navigation Aid Section
//=================================================================================================

	private void prepareToCallout(URL url) {
		if (callout != null) {
			// prevent animations from lingering when moving to new pages
			callout.dispose();
			callout = null;
		}

		callout = new CalloutRequest(this, htmlEditorPane, url);
		callout.runLater();
	}

	private class HelpIDChangedListener implements HelpModelListener {
		@Override
		public void idChanged(HelpModelEvent e) {
			prepareToCallout(e.getURL());
		}
	}

}
