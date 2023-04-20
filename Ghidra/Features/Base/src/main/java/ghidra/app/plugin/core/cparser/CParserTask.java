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

import javax.swing.SwingUtilities;

import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 *  Background task to parse files for cparser plugin
 * 
 * 
 */
class CParserTask extends Task {

	private CParserPlugin plugin;
	private String dataFileName;
	
	private String[] filenames;
	private String[] includePaths;
	
	private String options;
	
	private String languageString;
	private String compilerString;
	
	private DataTypeManager dtMgr;


	/**
	 * Create task to parse to a dataFile
	 * 
	 * @param plugin CParserPlugin that will do the work
	 * @param dataFileName name of the file to parse to
	 */
	CParserTask(CParserPlugin plugin, String dataFileName) {
		super("Parsing C Files", true, false, false);

		this.plugin = plugin;
		this.dataFileName = dataFileName;
	}

	/**
	 * Create task to parse to a dataTypeManager
	 * 
	 * @param plugin
	 * @param dataTypeManager
	 */
	public CParserTask(CParserPlugin plugin, DataTypeManager dataTypeManager) {
		super("Parsing C Files", true, false, false);

		this.plugin = plugin;
		this.dtMgr = dataTypeManager;
	}

	/**
	 * Create task to parse to a ProgramDataTypeManager
	 * 
	 * @param plugin
	 * @param dataTypeManager
	 */
	public CParserTask(CParserPlugin plugin, ProgramBasedDataTypeManager dataTypeManager) {
		super("Parsing C Files", true, false, false);
		
		this.plugin = plugin;
		this.dtMgr = dataTypeManager;
	}
	
	public CParserTask setLanguageID(String languageID) {
		this.languageString = languageID;
		return this;
	}
	
	public CParserTask setCompilerID(String compilerID) {
		this.compilerString = compilerID;
		return this;
	}
	
	public CParserTask setIncludePaths(String includePaths[]) {
		this.includePaths = includePaths.clone();
		return this;
	}
	
	public CParserTask setFileNames(String names[]) {
		this.filenames = names.clone();
		return this;
	}
	
	public CParserTask setOptions(String options) {
		this.options = options;
		return this;
	}

	private String getFirstMessageLine(final String errMsg) {
		int indexOf = errMsg.indexOf('\n');
		String msg = errMsg;
		if (indexOf > 0) {
			msg = msg.substring(0, indexOf);
		}
		return msg;
	}

	@Override
	public void run(TaskMonitor monitor) {
		DataTypeManager fileDtMgr = null;
		try {
			if (dtMgr == null) {
				File file = new File(dataFileName);
				dtMgr = FileDataTypeManager.createFileArchive(file);
				fileDtMgr = dtMgr;
			}

			plugin.parse(filenames, includePaths, options, languageString, compilerString, dtMgr, monitor);
			if (dataFileName != null) {
				// TODO: does not consider existing datatypes
				if (dtMgr.getDataTypeCount(true) != 0) {
					try {
						((FileDataTypeManager) dtMgr).save();
						dtMgr.close();
					}
					catch (DuplicateFileException e) {
						Msg.showError(this, plugin.getDialog().getComponent(), "Error During Save",
							e.getMessage());
					}
					catch (Exception e) {
						Msg.showError(this, plugin.getDialog().getComponent(), "Error During Save",
							"Could not save to file " + dataFileName, e);
					}
					finally {
						if (dtMgr instanceof FileDataTypeManager) {
							dtMgr.close();
						}
					}
				}
				else {
					SwingUtilities.invokeLater(new Runnable() {
						@Override
						public void run() {
							// no results, was canceled
							if (plugin.getParseResults() == null) {
								return;
							}
							MultiLineMessageDialog.showModalMessageDialog(
								plugin.getDialog().getComponent(), "Parse Errors",
								"File was not created due to parse errors: " +
									((FileDataTypeManager) dtMgr).getFilename(),
								plugin.getFormattedParseMessage(null),
								MultiLineMessageDialog.INFORMATION_MESSAGE);
						}
					});
				}
			}
		}
		catch (ghidra.app.util.cparser.C.ParseException e) {
			final String errMsg = e.getMessage();
			System.err.println(errMsg);
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					String msg = getFirstMessageLine(errMsg);
					MultiLineMessageDialog.showModalMessageDialog(plugin.getDialog().getComponent(),
						"Parse Errors", msg, plugin.getFormattedParseMessage(errMsg),
						MultiLineMessageDialog.ERROR_MESSAGE);
				}
			});
		}
		catch (ghidra.app.util.cparser.CPP.ParseException e) {
			final String errMsg = e.getMessage();
			System.err.println(errMsg);
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					String msg = getFirstMessageLine(errMsg);
					MultiLineMessageDialog.showModalMessageDialog(plugin.getDialog().getComponent(),
						"PreProcessor Parse Errors", msg, plugin.getFormattedParseMessage(errMsg),
						MultiLineMessageDialog.ERROR_MESSAGE);
				}
			});
		}
		catch (Exception e) {
			final String errMsg = e.getMessage();
			String msg = getFirstMessageLine(errMsg);
			Msg.showError(this, plugin.getDialog().getComponent(), "Error During Parse",
				"Parse header files failed" + "\n\nParser Messages:\n" + plugin.getParseMessage(),
				e);
			MultiLineMessageDialog.showModalMessageDialog(plugin.getDialog().getComponent(),
				"Error During Parse", msg, plugin.getFormattedParseMessage(errMsg),
				MultiLineMessageDialog.ERROR_MESSAGE);
		}
		finally {
			if (fileDtMgr != null) {
				fileDtMgr.close();
			}
		}
	}
}
