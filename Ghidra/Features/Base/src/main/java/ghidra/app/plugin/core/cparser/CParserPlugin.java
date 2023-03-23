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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.StringTokenizer;

import javax.swing.SwingUtilities;

import org.apache.commons.io.DirectoryWalker.CancelException;

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
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.CPP.PreProcessor;
import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
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
	final static String PARSE_ACTION_NAME = "Import C DataTypes";

	final static String USER_PROFILES_DIR =
		Application.getUserSettingsDirectory().getAbsolutePath() + File.separatorChar +
			"parserprofiles";
	private ParseDialog parseDialog;
	private File userProfileDir;

	private String parserMessages;
	private String cppMessages;

	final static String DESCRIPTION =
		"Parse C and C Header files, extracting data definitions and function signatures.";

	private static final String PARSER_DEBUG_OUTFILE = "CParserPlugin.out";

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
		else {
			parseDialog.toFront();
		}
		tool.showDialog(parseDialog);
	}

	/*
	 * Parse into a saved data type data base file
	 */
	protected void parse(String[] filenames, String options, String dataFilename) {
		CParserTask parseTask = new CParserTask(this, filenames, options, dataFilename);
		this.getTool().execute(parseTask, 500);
	}

	/*
	 * Parse C-source into a data type manager
	 */
	protected void parse(String[] filenames, String options, DataTypeManager dtMgr,
			TaskMonitor monitor) throws ghidra.app.util.cparser.C.ParseException,
			ghidra.app.util.cparser.CPP.ParseException {
		String[] args = parseOptions(options);

		DataTypeManager openDTmanagers[] = null;
		try {
			openDTmanagers = getOpenDTMgrs();
		} catch (CancelledException exc) {
			return; // parse canceled
		}

		cppMessages = "";
		PreProcessor cpp = new PreProcessor();

		cpp.setArgs(args);

		PrintStream os = System.out;
		String homeDir = System.getProperty("user.home");
		String fName = homeDir + File.separator + "CParserPlugin.out";
		try {
			os = new PrintStream(new FileOutputStream(fName));
		}
		catch (FileNotFoundException e2) {
			Msg.error(this, "Unexpected Exception: " + e2.getMessage(), e2);
		}

		PrintStream old = System.out;
		System.setOut(os);

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		cpp.setOutputStream(bos);

		try {
			for (String filename : filenames) {
				if (monitor.isCancelled()) {
					break;
				}
				// any file beginning with a "#" is assumed to be a comment
				if (filename.trim().startsWith("#")) {
					continue;
				}
				File file = new File(filename);

				if (file.isDirectory()) {
					// process each header file in the directory
					String[] children = file.list();
					if (children == null) {
						continue;
					}
					for (String element : children) {
						File child = new File(file.getAbsolutePath() + "/" + element);
						if (child.getName().endsWith(".h")) {
							parseFile(child.getAbsolutePath(), monitor, cpp);
						}
					}
				}
				else {
					parseFile(filename, monitor, cpp);
				}
			}
		}
		catch (RuntimeException re) {
			os.close();
			throw new ghidra.app.util.cparser.CPP.ParseException(re.getMessage());
		}

		// process all the defines and add any that are integer values into
		// the Equates table
		cpp.getDefinitions().populateDefineEquates(openDTmanagers, dtMgr);

		System.out.println(bos.toString());

		System.setOut(old);
		os.close();

		if (!monitor.isCancelled()) {
			monitor.setMessage("Parsing C");

			CParser cParser = new CParser(dtMgr, true, openDTmanagers);
			cParser.setParseFileName(PARSER_DEBUG_OUTFILE);
			ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
			try {
				parserMessages = "";
				cParser.setParseFileName(fName);
				cParser.parse(bis);
			}
			finally {
				parserMessages = cParser.getParseMessages();
			}

			final boolean isProgramDtMgr = (dtMgr instanceof ProgramDataTypeManager);

			SwingUtilities.invokeLater(() -> {
				// CParserTask will show any errors
				if (!cParser.didParseSucceed()) {
					return;
				}
				if (isProgramDtMgr) {
					MultiLineMessageDialog.showModalMessageDialog(parseDialog.getComponent(),
						"C-Parse of Header Files Complete",
						"Successfully parsed header file(s) to Program.",
						getFormattedParseMessage(
							"Check the Manage Data Types window for added data types."),
						MultiLineMessageDialog.INFORMATION_MESSAGE);
				}
				else {
					String archiveName = dtMgr.getName();
					if (dtMgr instanceof FileDataTypeManager) {
						archiveName = ((FileDataTypeManager) dtMgr).getFilename();
					}
					MultiLineMessageDialog.showModalMessageDialog(parseDialog.getComponent(),
						"C-Parse of Header Files Complete. ",
						"Successfully parsed header file(s) to Archive File:  " + archiveName,
						getFormattedParseMessage(null), MultiLineMessageDialog.INFORMATION_MESSAGE);
				}
			});
		}

	}

	/**
	 * Get open data type managers.
	 *    User can Use Open managers, Select not to use, or Cancel
	 *    
	 * @param openDTmanagers open mgrs, null if don't use
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
			"Use Open Archives?", "Don't Use Open Archives", OptionDialog.QUESTION_MESSAGE);
		    if (result == OptionDialog.CANCEL_OPTION) {
		    	throw new CancelledException("User Cancelled");
		    }
		    if (result == OptionDialog.OPTION_TWO) {
		    	return null;
		    }
		}

		return openDTmanagers;
	}

	public String getFormattedParseMessage(String errMsg) {
		String message = "";

		if (errMsg != null) {
			message += errMsg + "\n\n";
		}

		String msg = getParseMessage();
		if (msg != null && msg.length() != 0) {
			message += "CParser Messages:\n" + msg + "\n\n";
		}

		msg = getPreProcessorMessage();
		if (msg != null && msg.length() != 0) {
			message += "PreProcessor Messages:\n" + getPreProcessorMessage();
		}

		return message;
	}

	/**
	 * Get any parse messages produced by parsing good, or informational
	 * 
	 * @return messages from parser
	 */
	public String getParseMessage() {
		return parserMessages;
	}

	public String getPreProcessorMessage() {
		return cppMessages;
	}

	private void parseFile(String filename, TaskMonitor monitor, PreProcessor cpp)
			throws ghidra.app.util.cparser.CPP.ParseException {
		monitor.setMessage("PreProcessing " + filename);
		try {
			Msg.info(this, "parse " + filename);
			cpp.parse(filename);
		}
		catch (Throwable e) {
			Msg.error(this, "Parsing file :" + filename);
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);

			throw new ghidra.app.util.cparser.CPP.ParseException(e.getMessage());
		}
		finally {
			cppMessages += cpp.getParseMessages();
		}
	}

	/*
	 * Parse into the current programs data type manager
	 */
	protected void parse(String[] filenames, String options) {
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
			new CParserTask(this, filenames, options, currentProgram.getDataTypeManager());

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
