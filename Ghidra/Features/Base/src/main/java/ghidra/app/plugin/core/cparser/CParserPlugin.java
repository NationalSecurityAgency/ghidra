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
package ghidra.app.plugin.core.cparser;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.StringTokenizer;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "C Code Parser",
	description = CParserPlugin.DESCRIPTION
)
//@formatter:on
public class CParserPlugin extends ProgramPlugin {
	public final static String PARSE_ACTION_NAME = "Import C DataTypes";

	final static String USER_PROFILES_DIR =
		Application.getUserSettingsDirectory().getAbsolutePath() + File.separatorChar +
			"parserprofiles";
	
	private ParseDialog parseDialog;
	private File userProfileDir;

	private CParseResults results;

	final static String DESCRIPTION =
		"Parse C and C Header files, extracting data definitions and function signatures.";

	public CParserPlugin(PluginTool plugintool) {
		super(plugintool);
		createActions();
		setUserProfileDir(USER_PROFILES_DIR);
	}

	/*package*/ void setUserProfileDir(String path) {
		userProfileDir = new File(path);
		userProfileDir.mkdir();
	}

	/*package*/ File getUserProfileDir() {
		return userProfileDir;
	}

	public boolean isSingleton() {
		return true;
	}

	public Program getProgram() {
		return currentProgram;
	}

	@Override
	public void dispose() {
		if (parseDialog != null) {
			parseDialog.close();
			parseDialog = null;
		}
	}

	@Override
	public void readDataState(SaveState saveState) {
		parseDialog = new ParseDialog(this);
		parseDialog.readState(saveState);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		if (parseDialog != null) {
			parseDialog.writeState(saveState);
		}
	}

	@Override
	protected boolean canClose() {
		if (parseDialog != null) {
			parseDialog.closeProfile();
		}
		return true;
	}

	private void createActions() {
		DockingAction parseAction = new DockingAction(PARSE_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showParseDialog();
			}
		};
		String[] menuPath = { ToolConstants.MENU_FILE, "Parse C Source..." };
		MenuData menuData = new MenuData(menuPath, "Import/Export");
		menuData.setMenuSubGroup("d"); // below the major actions in the "Import/Export" group
		parseAction.setMenuBarData(menuData);
		parseAction.setDescription(DESCRIPTION);
		parseAction.setHelpLocation(new HelpLocation(this.getName(), "Parse_C_Source"));
		parseAction.setEnabled(true);
		tool.addAction(parseAction);
	}

	protected void showParseDialog() {
		if (parseDialog == null) {
			parseDialog = new ParseDialog(this);
		}
		parseDialog.setupForDisplay();
		tool.showDialog(parseDialog);
	}

	/*
	 * Parse into a saved data type data base file
	 */
	protected void parse(String[] filenames, String includePaths[], String options,
		String languageIDString, String compilerSpecID, String dataFilename) {
		
		CParserTask parseTask = new CParserTask(this, dataFilename)
				.setFileNames(filenames)
				.setIncludePaths(includePaths)
				.setOptions(options)
				.setLanguageID(languageIDString)
				.setCompilerID(compilerSpecID);
		
		this.getTool().execute(parseTask, 500);
	}

	
	/*
	 * Parse C-source into a data type manager
	 */
	protected void parse(String[] filenames, String includePaths[], String options, 
			String languageIDString, String compilerSpecID, DataTypeManager dtMgr,
			TaskMonitor monitor) throws ghidra.app.util.cparser.C.ParseException,
			ghidra.app.util.cparser.CPP.ParseException {

		results = null;
		
		String[] args = parseOptions(options);

		DataTypeManager openDTmanagers[] = null;
		try {
			openDTmanagers = getOpenDTMgrs();
		} catch (CancelledException exc) {
			return; // parse canceled
		}

		try {
			results = CParserUtils.parseHeaderFiles(openDTmanagers, filenames, includePaths,
					args, dtMgr, languageIDString, compilerSpecID, monitor);
			
			final boolean isProgramDtMgr = (dtMgr instanceof ProgramDataTypeManager);
	
			SwingUtilities.invokeLater(() -> {
				// CParserTask will show any errors
				if (!results.successful()) {
					return;
				}
				if (isProgramDtMgr) {
					MultiLineMessageDialog.showModalMessageDialog(parseDialog.getComponent(),
						"C-Parse of Header Files Complete",
						"Successfully parsed header file(s) to Program.",
						getFormattedParseMessage("Check the Manage Data Types window for added data types."),
						MultiLineMessageDialog.INFORMATION_MESSAGE);
				}
				else {
					String archiveName = dtMgr.getName();
					if (dtMgr instanceof FileDataTypeManager) {
						archiveName = ((FileDataTypeManager) dtMgr).getFilename();
					}
					MultiLineMessageDialog.showModalMessageDialog(parseDialog.getComponent(),
						"C-Parse of Header Files Complete",
						"Successfully parsed header file(s) to Archive File:  " + archiveName,
						getFormattedParseMessage(null),
						MultiLineMessageDialog.INFORMATION_MESSAGE);
				}
			});
		}
		catch (IOException e) {
			// ignore
		}
	}

	/**
	 * Get open data type managers.
	 *    User can Use Open managers, Select not to use, or Cancel
	 *    
	 * @return array of open data type managers
	 * 
	 * @throws CancelledException if user cancels
	 */
	private DataTypeManager[] getOpenDTMgrs() throws CancelledException {
		DataTypeManager[] openDTmanagers = null;
		
		DataTypeManagerService dtService = tool.getService(DataTypeManagerService.class);
		if (dtService == null) {
			return openDTmanagers;
		}
		
		openDTmanagers = dtService.getDataTypeManagers();

		ArrayList<DataTypeManager> list = new ArrayList<>();
		String htmlNamesList = "";
		for (DataTypeManager openDTmanager : openDTmanagers) {
			if (openDTmanager instanceof ProgramDataTypeManager) {
				continue;
			}
			list.add(openDTmanager);
			if (!(openDTmanager instanceof BuiltInDataTypeManager)) {
				htmlNamesList +=
					"<li><b>" + HTMLUtilities.escapeHTML(openDTmanager.getName()) + "</b></li>";
			}
		}
		openDTmanagers = list.toArray(new DataTypeManager[0]);

		if (openDTmanagers.length > 1) {
		    int result = OptionDialog.showOptionDialog(
			this.parseDialog.getComponent(), "Use Open Archives?",
			"<html>The following archives are currently open: " + "<ul>" + htmlNamesList +
				"</ul>" + "<p><b>The new archive will become dependent on these archives<br>" +
				"for any datatypes already defined in them </b>(only unique <br>" +
				"data types will be added to the new archive).",
			"Use Open Archives", "Don't Use Open Archives", OptionDialog.QUESTION_MESSAGE);
		    if (result == OptionDialog.CANCEL_OPTION) {
		    	throw new CancelledException("User Cancelled");
		    }
		    if (result == OptionDialog.OPTION_TWO) {
		    	return null;
		    }
		}

		return openDTmanagers;
	}
	
	public CParseResults getParseResults() {
		return results;
	}
	
	public String getParseMessage() {
		return (results != null ? results.cParseMessages() : "");
	}

	protected String getFormattedParseMessage(String errMsg) {
		String message = "";

		if (errMsg != null) {
			message += errMsg + "\n\n";
		}

		String msg = (results == null ? null : results.cParseMessages());
		if (msg != null && msg.length() != 0) {
			message += "CParser Messages:\n" + msg + "\n\n";
		}

		msg = (results == null ? null : results.cppParseMessages());
		if (msg != null && msg.length() != 0) {
			message += "PreProcessor Messages:\n" + msg;
		}

		return message;
	}

	/*
	 * Parse into the current programs data type manager
	 */
	protected void parse(String[] filenames, String[] includePaths, String options,
			String languageIDString, String compilerIDString) {
		if (currentProgram == null) {
			Msg.showInfo(getClass(), parseDialog.getComponent(), "No Open Program",
				"A program must be open to \"Parse to Program\"");
			return;
		}
		int result = OptionDialog.showOptionDialog(parseDialog.getComponent(), "Confirm",
			"Parse C source to \"" + currentProgram.getDomainFile().getName() + "\"?", "Continue");

		if (result == OptionDialog.CANCEL_OPTION) {
			return;
		}

		CParserTask parseTask =
			new CParserTask(this, currentProgram.getDataTypeManager())
			.setFileNames(filenames)
			.setIncludePaths(includePaths)
			.setOptions(options)
			.setLanguageID(languageIDString)
			.setCompilerID(compilerIDString);

		tool.execute(parseTask);
	}

	ParseDialog getDialog() {
		return parseDialog;
	}

	private String[] parseOptions(String options) {
		ArrayList<String> list = new ArrayList<>();

		StringTokenizer toker = new StringTokenizer(options, "\r\n");
		while (toker.hasMoreTokens()) {
			String val = toker.nextToken();
			val = val.trim();
			StringBuffer arg = new StringBuffer();
			boolean parseQuote = false;
			int index = 0;
			while (index < val.length()) {
				char ch = val.charAt(index++);
				switch (ch) {
					case '"':
						// turn on/off quoting, don't copy in '"'
						parseQuote = !parseQuote;
						break;
					case '-':
						if (!parseQuote) {
							String sarg = arg.toString().trim();
							if (sarg.length() > 0) {
								list.add(sarg);
							}
						}
					default:
						arg.append(ch);
				}
			}
			String sarg = arg.toString().trim();
			if (sarg.length() > 0) {
				list.add(sarg);
			}
		}

		return list.toArray(new String[list.size()]);
	}
}
