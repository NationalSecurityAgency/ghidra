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
	 *  Used when placing an action in the "Project" menu of the tool
	 */
	public static final String MENU_PROJECT = "&Project";

	/**
	 *  Used when placing an action in the "Tools" menu of the tool
	 */
	public static final String MENU_TOOLS = "&Tools";

	/** A group for actions that link directly to help content */
	public static final String HELP_CONTENTS_MENU_GROUP = "AAAHelpContents";

	/** Used for navigation-based action */
	public static final String NEXT_CODE_UNIT_NAVIGATION_MENU_GROUP = "NextPrevCodeUnit";

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
	 * Name of options for a tool
	 */
	public static final String TOOL_OPTIONS = "Tool";

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

	/**
	 * The large icon size (height and width)
	 */
	public static final int LARGE_ICON_SIZE = 24;

	/**
	 * The medium icon size (height and width)
	 */
	public static final int MEDIUM_ICON_SIZE = 22;

	/**
	 * The small icon size (height and width)
	 */
	public static final int SMALL_ICON_SIZE = 16;

}
