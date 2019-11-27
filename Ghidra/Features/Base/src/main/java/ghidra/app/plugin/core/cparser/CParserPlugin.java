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

import java.io.*;
import java.util.ArrayList;
import java.util.StringTokenizer;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.CPP.PreProcessor;
import ghidra.app.util.xml.DataTypesXmlMgr;
import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
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

	final static String DESCRIPTION =
		"Parse C and C Header files, extracting data definitions and function signatures.";

	public CParserPlugin(PluginTool plugintool) {
		super(plugintool, false, false);
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

	public void doCParser() {

		try {
			// PreProcessor cpp = new PreProcessor("c:/Program Files/Microsoft
			// Visual Studio/VC98/Include/stdio.h");
			String filename1 = "c:/Program Files/Microsoft Visual Studio/VC98/Include/windows.h";
			// String filename1 = "c:/Program Files/Microsoft Visual
			// Studio/VC98/Include/stdio.h";
			// String filename1 = "c:/dummy.h";
			// String filename2 = "c:/Program Files/Microsoft Visual
			// Studio/VC98/Include/winnt.h";
			String[] args = { "-Ic:/Program Files/Microsoft Visual Studio/VC98/Include/",
				// "-D_DLL",
				"-D_M_IX86=500", "-D_MSC_VER=9090", "-D_WIN32_WINNT=0x0400",
				"-D_WIN32_WINDOWS=0x400", "-D_INTEGRAL_MAX_BITS=32", "-D_X86_", "-D_WIN32" };
			PreProcessor cpp = new PreProcessor();
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			cpp.setArgs(args);
			OutputStream os = null;
			try {
				os = new FileOutputStream("c:/tmpwindows.h.out");
			}
			catch (FileNotFoundException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			PrintStream ps = new PrintStream(os);
			System.setErr(ps);
			System.setOut(ps);
			cpp.setOutputStream(bos);
			try {
				cpp.parse(filename1);
			}
			catch (RuntimeException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}

			System.out.println(bos);

			FileDataTypeManager dtMgr =
				FileDataTypeManager.createFileArchive(new File("c:/parse.gdt"));
			CParser cParser = new CParser(dtMgr, true, null);
			ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
			cParser.parse(bis);

			try {
				DataTypesXmlMgr.writeAsXMLForDebug(dtMgr, "c:/parse.xml");
				dtMgr.save();
				dtMgr.close();
			}
			catch (IOException e3) {
				Msg.error(this, "Unexpected Exception: " + e3.getMessage(), e3);
			}
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	// // Prints out all the types used in parsing the c source
	// private DataTypeManager populateTypes(CParser parser) {
	// DataTypeManager dtMgr = new DataTypeManagerImpl("parsed");
	//
	// addTypes(dtMgr, parser.getFunctions());
	// addTypes(dtMgr, parser.getDeclarations());
	// addTypes(dtMgr, parser.getEnums());
	// addTypes(dtMgr, parser.getStructs());
	// addTypes(dtMgr, parser.getTypes());
	//
	// moveTypes("Functions", dtMgr, parser.getFunctions());
	// moveTypes("Declarations", dtMgr, parser.getDeclarations());
	// moveTypes("Enums", dtMgr, parser.getEnums());
	// moveTypes("Structs", dtMgr, parser.getStructs());
	// moveTypes("Types", dtMgr, parser.getTypes());
	//
	// return dtMgr;
	// }
	//
	// private void addTypes(DataTypeManager dtMgr, Hashtable table) {
	// Category rootCat = dtMgr.getRootCategory();
	//
	// Enumeration enum = table.keys();
	// while (enum.hasMoreElements()) {
	// String name = (String) enum.nextElement();
	// DataType dt = null;
	// Object obj = table.get(name);
	// if (obj instanceof DataType) {
	// dt = (DataType) obj;
	// }
	// if (dt instanceof TypedefDataType) {
	// TypedefDataType tdt = (TypedefDataType) dt;
	// if (tdt instanceof Composite) {
	// if (tdt.getName().equals(tdt.getBaseDataType().getName())) {
	// continue;
	// }
	// }
	// }
	// if (dt != null) {
	// dumpDT(name, dt);
	// dt = rootCat.addDataType(dt);
	// dumpDT(name, dt);
	// table.put(name, dt);
	// }
	// }
	// }
	//

//	private void dumpDT(String name, DataType dt) {
//		if (dt instanceof StructureDataType) {
//			StructureDataType sdt = (StructureDataType) dt;
//			Err.debug(this, "struct " + sdt.getName() + "   "
//					+ sdt.getNumComponents());
//			CategoryPath cat = sdt.getCategoryPath();
//			Err.debug(this, "    "
//					+ (cat != null ? cat.getName() : " -nocat-"));
//			for (int i = 0; i < sdt.getNumComponents(); i++) {
//				DataTypeComponent ndt = sdt.getComponent(i);
//				Err.debug(this, "   " + ndt.getFieldName() + "  "
//						+ ndt.getLength() + "   " + ndt.getOffset());
//			}
//		} else if (dt instanceof TypedefDataType) {
//			TypedefDataType tdt = (TypedefDataType) dt;
//			Err.debug(this, "typedef " + tdt.getBaseDataType().getName()
//					+ "   " + dt.getName());
//		} else {
//			Err.debug(this, "      " + dt.getName());
//		}
//	}

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
		DataTypeManagerService dtService = tool.getService(DataTypeManagerService.class);
		if (dtService != null) {
			openDTmanagers = dtService.getDataTypeManagers();

			ArrayList<DataTypeManager> list = new ArrayList<>();
			String htmlNamesList = "";
			for (int i = 0; i < openDTmanagers.length; i++) {
				if (openDTmanagers[i] instanceof ProgramDataTypeManager) {
					continue;
				}
				list.add(openDTmanagers[i]);
				if (!(openDTmanagers[i] instanceof BuiltInDataTypeManager)) {
					htmlNamesList += "<li><b>" +
						HTMLUtilities.escapeHTML(openDTmanagers[i].getName()) + "</b></li>";
				}
			}
			openDTmanagers = list.toArray(new DataTypeManager[0]);

			if (openDTmanagers.length > 1 && OptionDialog.showOptionDialog(
				this.parseDialog.getComponent(), "Use Open Archives?",
				"<html>The following archives are currently open: " + "<ul>" + htmlNamesList +
					"</ul>" + "<p><b>The new archive will become dependent on these archives<br>" +
					"for any datatypes already defined in them </b>(only unique <br>" +
					"data types will be added to the new archive).",
				"Continue?", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
				return;
			}
		}

		PreProcessor cpp = new PreProcessor();
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		cpp.setArgs(args);

		PrintStream os = System.out;
		try {
			String homeDir = System.getProperty("user.home");
			String fName = homeDir + File.separator + "CParserPlugin.out";
			os = new PrintStream(new FileOutputStream(fName));
		}
		catch (FileNotFoundException e2) {
			Msg.error(this, "Unexpected Exception: " + e2.getMessage(), e2);
		}
		// cpp.setOutputStream(os);
		PrintStream old = System.out;
		System.setOut(os);

		cpp.setOutputStream(bos);

		try {
			for (String filename : filenames) {
				if (monitor.isCancelled()) {
					break;
				}
				File file = new File(filename);
				// process each header file in the directory
				if (file.isDirectory()) {
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
			Msg.error(this, re.getMessage());
			os.close();
			return;
		}

		// process all the defines and add any that are integer values into
		// the Equates table
		cpp.getDefinitions().populateDefineEquates(dtMgr);

		System.out.println(bos);

		System.setOut(old);
		os.close();

		if (!monitor.isCancelled()) {
			monitor.setMessage("Parsing C");

			CParser cParser = new CParser(dtMgr, true, openDTmanagers);
			ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
			cParser.parse(bis);

			final boolean isProgramDtMgr = (dtMgr instanceof ProgramDataTypeManager);

			SwingUtilities.invokeLater(() -> {
				if (isProgramDtMgr) {
					Msg.showInfo(getClass(), parseDialog.getComponent(),
						"Parse Header Files Completed", "Successfully parsed header file(s).\n" +
							"Check the Manage Data Types window for added data types.");
				}
				else {
					parseDialog.setDialogText("Successfully parsed header file(s).");
				}
			});
		}

	}

	private void parseFile(String filename, TaskMonitor monitor, PreProcessor cpp) {
		monitor.setMessage("PreProcessing " + filename);
		try {
			Msg.info(this, "parse " + filename);
			cpp.parse(filename);
		}
		catch (Throwable e) {
			Msg.error(this, "Parsing file :" + filename);
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
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
