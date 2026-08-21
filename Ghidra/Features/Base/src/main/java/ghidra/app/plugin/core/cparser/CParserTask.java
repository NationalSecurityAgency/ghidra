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

import javax.help.UnsupportedOperationException;
import javax.swing.SwingUtilities;

import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
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
	
	private String[] filenames;
	private String[] includePaths;
	
	private String options;
	
	// Language and Compiler Spec IDs valid only for new dataFileName use
	private String languageId;
	private String compilerSpecId;
	
	// Either dataTypeManager or dataFileName must be set, but not both
	private final DataTypeManager dataTypeManager; // specified for an existing DataTypeManager
	private final File dataFile; // specified for a new file

	/**
	 * Create task to parse to a dataFile
	 * 
	 * @param plugin CParserPlugin that will do the work
	 * @param dataFileName name of the file to parse to
	 */
	CParserTask(CParserPlugin plugin, String dataFileName) {
		super("Parsing C Files", true, false, false);
		dataTypeManager = null;
		this.plugin = plugin;
		this.dataFile = new File(dataFileName);
	}

	/**
	 * Create task to parse to a dataTypeManager
	 * 
	 * NOTE: The Language ID and Compiler Spec ID must not be set since the dataTypeManager's
	 * current architecture will be used.
	 * 
	 * @param plugin CParserPlugin that will do the work
	 * @param dataTypeManager target data type manager
	 */
	public CParserTask(CParserPlugin plugin, DataTypeManager dataTypeManager) {
		super("Parsing C Files", true, false, false);
		dataFile = null;
		this.plugin = plugin;
		this.dataTypeManager = dataTypeManager;
	}

	/**
	 * Set the language ID to be used.
	 * 
	 * NOTE: The compiler spec ID must also be set, see {@code #setCompilerID(String)}.
	 * See language *.ldefs file for defined compiler spec IDs or existing Program info.
	 * 
	 * @param languageId language ID
	 * @return this task
	 * @throws UnsupportedOperationException if task was constructed with a DataTypeManager whose
	 * existing architecture will be used.
	 */
	public CParserTask setLanguageID(String languageId) {
		if (dataTypeManager != null) {
			throw new UnsupportedOperationException(
				"setLanguageID not supported when constructed with DataTypeManager");
		}
		this.languageId = languageId;
		return this;
	}
	
	/**
	 * Set the compiler spec ID to be used.  This ID must be defined for the specified language.
	 * 
	 * NOTE: The language ID must also be set, see {@code #setLanguageID(String)}.
	 * See language *.ldefs file for defined compiler spec IDs or existing Program info.
	 * 
	 * @param compilerSpecId compiler spec ID
	 * @return this task
	 * @throws UnsupportedOperationException if task was constructed with a DataTypeManager whose
	 * existing architecture will be used.
	 */
	public CParserTask setCompilerID(String compilerSpecId) {
		if (dataTypeManager != null) {
			throw new UnsupportedOperationException(
				"setLanguageID not supported when constructed with DataTypeManager");
		}
		this.compilerSpecId = compilerSpecId;
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

	private String getResultMessage(DataTypeManager dtMgr, int initialDtCount) {

		int finalDtCount = dtMgr.getDataTypeCount(true) - initialDtCount;

		String msg = (finalDtCount == 0 ? "No" : Integer.toString(finalDtCount)) +
			" Data Types added.";
		if (finalDtCount != 0 && plugin.isOpenInTool(dtMgr)) {
			msg += "\nCheck the Data Type Manager window for added data types.";
		}
		return msg;
	}

	private String getParseDestination(DataTypeManager dtMgr) {
		String parseDest = "";
		if (dtMgr instanceof ProgramDataTypeManager) {
			parseDest = "Program " + dtMgr.getName();
		}
		else if (dtMgr instanceof FileDataTypeManager fileDtm) {
			parseDest = "Archive File: " + fileDtm.getFilename();
		}
		else {
			parseDest = dtMgr.getName();
		}
		return parseDest;
	}

	@Override
	public void run(TaskMonitor monitor) {

		FileDataTypeManager fileDtMgr = null;
		if (dataFile != null) {
			try {
				if ((languageId != null) != (compilerSpecId != null)) {
					Msg.showError(this, plugin.getDialog().getComponent(), "Archive Failure",
						"Language/CompilerSpec improperly specified: " + languageId + "/" +
							compilerSpecId);
					return;
				}
				fileDtMgr =
						FileDataTypeManager.createFileArchive(dataFile, languageId, compilerSpecId);
			}
			catch (IOException e) {
				Msg.showError(this, plugin.getDialog().getComponent(), "Archive Failure",
					"Failed to create archive datatype manager: " + e.getMessage());
				return;
			}
		}

		DataTypeManager dtMgr = fileDtMgr != null ? fileDtMgr : dataTypeManager;

		int initialDtCount = dtMgr.getDataTypeCount(true);

		try {

			CParseResults results = plugin.parse(filenames, includePaths, options, dtMgr, monitor);
			if (results == null) {
				return; // cancelled
			}

			if (fileDtMgr != null && dtMgr.getDataTypeCount(true) != 0) {
				// If archive created - save to file
				try {
					fileDtMgr.save();
				}
				catch (DuplicateFileException e) {
					Msg.showError(this, plugin.getDialog().getComponent(),
						"C-Parse Error During Save",
						e.getMessage());
				}
				catch (Exception e) {
					Msg.showError(this, plugin.getDialog().getComponent(),
						"C-Parse Error During Save",
						"Could not save to file " + dataFile.getPath(), e);
				}
			}

			String msg = getResultMessage(dtMgr, initialDtCount);

			SwingUtilities.invokeLater(() -> {
				if (!results.successful()) {
					MultiLineMessageDialog.showModalMessageDialog(
						plugin.getDialog().getComponent(), "C-Parse Failed",
						"Failed to parse header file(s) to " + getParseDestination(dtMgr),
						plugin.getFormattedParseMessage(msg),
						MultiLineMessageDialog.INFORMATION_MESSAGE);
				}
				else {
					MultiLineMessageDialog.showModalMessageDialog(
						plugin.getDialog().getComponent(),
						"C-Parse Completed",
						"Successfully parsed header file(s) to " + getParseDestination(dtMgr),
						plugin.getFormattedParseMessage(msg),
						MultiLineMessageDialog.INFORMATION_MESSAGE);
				}
			});
		}
		catch (ghidra.app.util.cparser.C.ParseException e) {
			final String errMsg = getResultMessage(dtMgr, initialDtCount) + "\n\n" + e.getMessage();
			SwingUtilities.invokeLater(() -> {
				MultiLineMessageDialog.showMessageDialog(plugin.getDialog().getComponent(),
					"C-Parse Failed",
					"Failed to parse header file(s) to " + getParseDestination(dtMgr),
					plugin.getFormattedParseMessage(errMsg),
					MultiLineMessageDialog.ERROR_MESSAGE);
			});
		}
		catch (ghidra.app.util.cparser.CPP.ParseException e) {
			final String errMsg = getResultMessage(dtMgr, initialDtCount) + "\n\n" + e.getMessage();
			SwingUtilities.invokeLater(() -> {
				MultiLineMessageDialog.showMessageDialog(plugin.getDialog().getComponent(),
					"C-PreProcessor Parse Failed",
					"Failed to parse header file(s) to " + getParseDestination(dtMgr),
					plugin.getFormattedParseMessage(errMsg),
					MultiLineMessageDialog.ERROR_MESSAGE);
			});
		}
		catch (Exception e) {
			final String errMsg = getResultMessage(dtMgr, initialDtCount) + "\n\n" + e.getMessage();
			Msg.showError(this, plugin.getDialog().getComponent(), "Error During C-Parse",
				"Parse header files failed" + "\n\nParser Messages:\n" + plugin.getParseMessage(),
				e);
			SwingUtilities.invokeLater(() -> {
				MultiLineMessageDialog.showMessageDialog(plugin.getDialog().getComponent(),
					"Error During C-Parse",
					"Failed to parse header file(s) to " + getParseDestination(dtMgr),
					plugin.getFormattedParseMessage(errMsg),
					MultiLineMessageDialog.ERROR_MESSAGE);
			});
		}
		finally {
			if (fileDtMgr != null) {
				boolean deleteFile = fileDtMgr.getDataTypeCount(true) == 0;
				fileDtMgr.close();
				if (deleteFile) {
					dataFile.delete();
				}
			}
		}
	}
}
