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
package docking.tool;

import docking.action.KeyBindingType;
import docking.tool.util.DockingToolConstants;

/**
 * Values used to define standard menu names and other miscellaneous constants
 */
public interface ToolConstants extends DockingToolConstants {

	/**
	 * Used when placing an action in the "File" menu of the tool
	 */
	public static final String MENU_FILE = "&File";

	/**
	 * Used when placing an action in the "Edit" menu of the tool
	 */
	public static final String MENU_EDIT = "&Edit";

	/**
	 * Used when placing a PluginAction in the "Navigation" menu of the tool
	 */
	public static final String MENU_NAVIGATION = "&Navigation";

	/**
	 * Group name for actions to navigate between windows
	 */
	public static final String MENU_NAVIGATION_GROUP_WINDOWS = "GoToWindow";

	/**
	 * Used when placing an action in the "Search" menu of the tool
	 */
	public static final String MENU_SEARCH = "&Search";

	/**
	 * Used when placing an action in the "Selection" menu of the tool
	 */
	public static final String MENU_SELECTION = "Se&lect";

	/**
	 * Used when placing an action in the "About" menu of the tool
	 */
	public static final String MENU_HELP = "&Help";

	/**
	 * Used when placing an action in the "Analysis" menu of the tool
	 */
	public static final String MENU_ANALYSIS = "&Analysis";

	/**
	 * Used when placing an action in the "Graph" menu of the tool
	 */
	public static final String MENU_GRAPH = "&Graph";

	/**
	 *  Used when placing an action in the "Project" menu of the tool
	 */
	public static final String MENU_PROJECT = "&Project";

	/**
	 *  Used when placing an action in the "Tools" menu of the tool
	 */
	public static final String MENU_TOOLS = "&Tools";

	/** A group for actions that link directly to help content */
	public static final String HELP_CONTENTS_MENU_GROUP = "AAAHelpContents";

	/**
	 * Constant for the options menu group for the Tool Options menu item
	 */
	public static final String TOOL_OPTIONS_MENU_GROUP = "AOptions";

	/**
	 * Node name used in the Data tree when a project is not open
	 */
	public static final String NO_ACTIVE_PROJECT = "NO ACTIVE PROJECT";

	/**
	 * This is used when an action has the tool as its owner
	 */
	public static final String TOOL_OWNER = "Tool";

	/**
	 * This is used when many actions wish to share a key binding.
	 * 
	 * @see KeyBindingType#SHARED
	 */
	public static final String SHARED_OWNER = "Shared";

	/**
	 * Tool options name
	 */
	public static final String TOOL_OPTIONS = "Tool";

	/**
	 * Graph options name
	 */
	public static final String GRAPH_OPTIONS = "Graph";

	/**
	 * Name of the help topic for "About" domain objects and Ghidra
	 */
	public static final String ABOUT_HELP_TOPIC = "About";

	/**
	 * Name of help topic for the front end (Ghidra Project Window)
	 */
	public static final String FRONT_END_HELP_TOPIC = "FrontEndPlugin";

	/**
	 * Name of help topic for the Tool
	 */
	public static final String TOOL_HELP_TOPIC = "Tool";

	/** Used for navigation-based action */
	public static final String MENU_GROUP_NEXT_CODE_UNIT_NAV = "NextPrevCodeUnit";

	/**
	 * Primary toolbar group number 1, starting from the left
	 */
	public static final String TOOLBAR_GROUP_ONE = "1_Toolbar_Navigation_Group";

	/**
	 * Primary toolbar group number 2, starting from the left
	 */
	public static final String TOOLBAR_GROUP_TWO = "2_Toolbar_Navigation_Group";

	/**
	 * Primary toolbar group number 3, starting from the left
	 */
	public static final String TOOLBAR_GROUP_THREE = "3_Toolbar_Navigation_Group";

	/**
	 * Primary toolbar group number 4, starting from the left
	 */
	public static final String TOOLBAR_GROUP_FOUR = "4_Toolbar_Navigation_Group";
}
