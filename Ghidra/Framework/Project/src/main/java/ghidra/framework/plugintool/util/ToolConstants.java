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
package ghidra.framework.plugintool.util;

import docking.tool.util.DockingToolConstants;

/**
 * Values used to define standard menu names and other miscellaneous
 * constants.
 */
public interface ToolConstants extends DockingToolConstants {
	/**
	 * Used when placing a PluginAction in the "File" menu of the tool.
	 */
	String MENU_FILE = "&File";
	/**
	 * Used when placing a PluginAction in the "Edit" menu of the tool.
	 */
	String MENU_EDIT = "&Edit";
	/**
	 * Used when placing a PluginAction in the "Navigation" menu of the tool.
	 */
	String MENU_NAVIGATION = "&Navigation";
	/**
	 * Used when placing a PluginAction in the "Search" menu of the tool.
	 */
	String MENU_SEARCH = "&Search";
	/**
	 * Used when placing a PluginAction in the "Selection" menu of the tool.
	 */
	String MENU_SELECTION = "Se&lect";

	/** A menu group that goes below those actions group with the "Select" menu grouping */
	public final static String MENU_SELECTION_UTILS_GROUP = "SelectUtils";

	/**
	 * Used when placing a PluginAction in the "View" menu of the tool.
	 */
//    String MENU_VIEW =                  "&View";

	/**
	 * Used when placing a PluginAction in the "About" menu of the tool.
	 */
	String MENU_HELP = "&Help";
	/**
	 * Used when placing a PluginAction in the "Analysis" menu of the tool.
	 */
	String MENU_ANALYSIS = "&Analysis";
	/**
	 *  Used when placing a PluginAction in the "Project" menu of the tool.
	 */
	String MENU_PROJECT = "&Project";
	/**
	 *  Used when placing a PluginAction in the "Tools" menu of the tool.
	 */
	String MENU_TOOLS = "&Tools";
	/**
	 *  Used when placing a PluginAction in the "Process" menu of the tool.
	 */
	String MENU_PROCESS = "&Process";
	/**
	 *  Used when placing a PluginAction in the "Trace" menu of the tool.
	 */
	String MENU_TRACE = "&Trace";
	/**
	 * Used when placing an action in the "Misc" menu of the tool.
	 */
	String MENU_MISC = "&Misc";

	/** Used for navigation-based action */
	String NEXT_CODE_UNIT_NAVIGATION_MENU_GROUP = "NextPrevCodeUnit";

	/**
	 * The standard icon size (height and width).
	 */
	int LARGE_ICON_SIZE = 24;

	int MEDIUM_ICON_SIZE = 22;

	int SMALL_ICON_SIZE = 16;

	/**
	 * Node name used in the Data tree when a project is not open.
	 */
	final static String NO_ACTIVE_PROJECT = "NO ACTIVE PROJECT";

	/**
	 * Name of options for a tool.
	 */
	public final static String TOOL_OPTIONS = "Tool";

	/**
	 * Constant for the options menu group for the Tool Options menu item.
	 */
	public final static String TOOL_OPTIONS_MENU_GROUP = "AOptions";

	/**
	 * Name of help topic for the front end (Ghidra Project Window).
	 */
	public final static String FRONT_END_HELP_TOPIC = "FrontEndPlugin";
	/**
	 * Name of the help topic for "About" domain objects and Ghidra.
	 */
	public final static String ABOUT_HELP_TOPIC = "About";
	/**
	 * Name of the help topic for "Report Bug".
	 */
	public final static String REPORT_BUG_TOPIC = "Intro";

	public final static String MENU_LAST_GROUP = "";

	/** A group for actions that link directly to help content */
	public final static String HELP_CONTENTS_MENU_GROUP = "AAAHelpContents";

}
