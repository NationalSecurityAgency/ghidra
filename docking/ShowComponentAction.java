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
package docking;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * Action for showing components.  If the component is hidden it will be made visible.
 * If it is tabbed, it will become the top tab. In all cases it will receive focus.
 */
class ShowComponentAction extends DockingAction implements Comparable<ShowComponentAction> {
	private static final int MAX_LENGTH = 40;

	protected static final ImageIcon EMPTY_ICON =
		ResourceManager.loadImage("images/EmptyIcon16.gif");
	protected static final String MENU_WINDOW = "&" + DockingWindowManager.COMPONENT_MENU_NAME;
	private ComponentPlaceholder info;
	protected DockingWindowManager winMgr;

	private static String truncateTitleAsNeeded(String title) {
		if (title.length() <= MAX_LENGTH) {
			return title;
		}

		return title.substring(0, MAX_LENGTH - 3) + "...";
	}

	protected ShowComponentAction(DockingWindowManager winMgr, String name, String subMenuName) {
		super(truncateTitleAsNeeded(name), DockingWindowManager.DOCKING_WINDOWS_OWNER);
	}

	/**
	 * Constructs a new ShowComponentAction object.
	 * @param winMgr the DockingWindowManager that this action belongs to.
	 * @param info the info of the component to be shown when this action is invoked.
	 */
	ShowComponentAction(DockingWindowManager winMgr, ComponentPlaceholder info, String subMenuName,
			boolean isTransient) {
		super(truncateTitleAsNeeded(info.getTitle()), DockingWindowManager.DOCKING_WINDOWS_OWNER);
		String group = isTransient ? "Transient" : "Permanent";

		Icon icon = info.getIcon();
		if (icon == null) {
			icon = EMPTY_ICON;
		}

		if (subMenuName != null) {
			setMenuBarData(new MenuData(
				new String[] { MENU_WINDOW, subMenuName, info.getFullTitle() }, icon, "Permanent"));
			winMgr.doSetMenuGroup(new String[] { MENU_WINDOW, subMenuName }, group);
		}
		else {
			setMenuBarData(
				new MenuData(new String[] { MENU_WINDOW, getName() }, icon, "Permanent"));
		}

		this.info = info;
		this.winMgr = winMgr;

		// Use provider Help for this action
		ComponentProvider provider = info.getProvider();
		HelpLocation helpLocation = provider.getHelpLocation();
		if (helpLocation != null) {
			setHelpLocation(helpLocation);
		}
		else {
			// This action only exists as a convenience for users to show a provider from the menu.
			// There is no need for this action itself to report errors if no help exists.
			markHelpUnnecessary();
		}
	}

	@Override
	public void actionPerformed(ActionContext context) {
		winMgr.showComponent(info, true, true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	// this compare method must take into account that there is sorting amongst top-level menus
	// and sub-menus, while understanding that they will all end up in one datastructure 
	@Override
	public int compareTo(ShowComponentAction other) {
		String[] myMenuPath = getMenuBarData().getMenuPath();
		String[] otherMenuPath = other.getMenuBarData().getMenuPath();

		// compare each path downward until they are no longer equal
		int loopLength = Math.min(myMenuPath.length, otherMenuPath.length);
		for (int i = 0; i < loopLength; i++) {
			int result = myMenuPath[i].compareTo(otherMenuPath[i]);
			if (result != 0) {
				return result;
			}
		}

		// return the smaller path first (arbitrary)
		return myMenuPath.length - otherMenuPath.length;
	}

	@Override
	public String getHelpInfo() {
		StringBuilder buffy = new StringBuilder(super.getHelpInfo());

		Class<? extends ComponentProvider> clazz = info.getProvider().getClass();
		String className = clazz.getName();
		String filename = className.substring(className.lastIndexOf('.') + 1);
		String javaName = filename + ".java";

		buffy.append("    ").append("PROVIDER:    ").append(info.getName()).append(' ');
		buffy.append('(').append(javaName).append(":1)");
		buffy.append("\n    ");

		return buffy.toString();
	}
}
