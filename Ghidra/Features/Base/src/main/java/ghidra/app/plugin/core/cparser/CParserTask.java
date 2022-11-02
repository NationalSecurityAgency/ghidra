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
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 *  This is called by the dialog box.
 * 
 * 
 */
class CParserTask extends Task {
	private String[] filenames;
	private String options;
	private CParserPlugin plugin;
	private String dataFileName;
	private DataTypeManager dtMgr;

	CParserTask(CParserPlugin plugin, String[] filenames, String options, String dataFileName) {
		super("Parsing C Files", true, false, false);

		this.plugin = plugin;
		this.filenames = filenames;
		this.options = options;
		this.dataFileName = dataFileName;
	}

	public CParserTask(CParserPlugin plugin, String[] filenames, String options,
			DataTypeManager dataTypeManager) {
		super("Parsing C Files", true, false, false);

		this.plugin = plugin;
		this.filenames = filenames;
		this.options = options;
		this.dtMgr = dataTypeManager;
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

			plugin.parse(filenames, options, dtMgr, monitor);
			if (dataFileName != null) {
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
