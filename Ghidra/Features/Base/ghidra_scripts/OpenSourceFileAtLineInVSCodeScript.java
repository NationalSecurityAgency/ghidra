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
// This script reads the source map information for the current address and uses it to open
// a source file in vs code at the appropriate line.  If there are multiple source map entries
// at the current address, the script displays a table to allow the user to select which ones
// to send to vs code.  The source file paths can be adjusted via 
// 
// Window -> Source Files and Transforms
//
// from the Code Browser.  The path to the vs code executable can be set via 
//
// Edit -> Tool Options -> Visual Studio Code Integration
//
// from the Ghidra Project Manager.
//@category SourceMapping

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.VSCodeIntegrationService;
import ghidra.app.tablechooser.*;
import ghidra.program.database.sourcemap.UserDataPathTransformer;
import ghidra.program.model.address.Address;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.sourcemap.SourcePathTransformer;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.TaskBuilder;

public class OpenSourceFileAtLineInVSCodeScript extends GhidraScript {

	private VSCodeIntegrationService vscodeService;
	protected SourcePathTransformer pathTransformer;
	protected File ideExecutableFile;

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			popup("This script cannot be run headlessly.");
			return;
		}
		if (currentProgram == null) {
			popup("This script requires an open program.");
			return;
		}

		List<SourceMapEntry> entries =
			currentProgram.getSourceFileManager().getSourceMapEntries(currentAddress);
		if (entries.isEmpty()) {
			popup("No source map entries found for " + currentAddress);
			return;
		}

		if (!verifyAndSetIdeExe()) {
			popup("Error acquiring IDE executable");
			return;
		}

		pathTransformer = UserDataPathTransformer.getPathTransformer(currentProgram);

		// if there is only one source map entry, send it to IDE
		if (entries.size() == 1) {
			SourceMapEntry entry = entries.get(0);
			openInIde(pathTransformer.getTransformedPath(entry.getSourceFile(), true),
				entry.getLineNumber());
		}
		// if there are multiple entries, pop up a table and let the user pick which ones
		// to send to IDE
		else {
			TableChooserDialog tableDialog =
				createTableChooserDialog("SourceMapEntries at " + currentAddress,
					new OpenInIdeExecutor());
			configureTableColumns(tableDialog);
			for (SourceMapEntry entry : entries) {
				tableDialog.add(new LocalPathRowObject(entry));
			}
			tableDialog.show();
		}
	}

	/**
	 * Sets the field {@code ideExecutableField}
	 * @return false if the IDE executable field could not be acquired
	 */
	protected boolean verifyAndSetIdeExe() {
		vscodeService = state.getTool().getService(VSCodeIntegrationService.class);
		if (vscodeService == null) {
			popup("VSCode service not configured for tool");
			return false;
		}
		try {
			ideExecutableFile = vscodeService.getVSCodeExecutableFile();
		}
		catch (FileNotFoundException e) {
			printerr(e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * Opens the source file at {@code transformedPath} at the given line number
	 * @param transformedPath source file path
	 * @param lineNumber line number
	 */
	protected void openInIde(String transformedPath, int lineNumber) {
		// transformedPath is a file uri path so it uses forward slashes 
		// File constructor on windows can accept such paths
		File localSourceFile = new File(transformedPath);
		if (!localSourceFile.exists()) {
			popup(transformedPath + " does not exist");
			return;
		}

		MonitoredRunnable r = m -> {
			try {
				List<String> args = new ArrayList<>();
				args.add(ideExecutableFile.getAbsolutePath());
				args.add("--goto");
				args.add(localSourceFile.getAbsolutePath() + ":" + lineNumber);
				new ProcessBuilder(args).redirectErrorStream(true).start();
			}
			catch (Exception e) {
				vscodeService.handleVSCodeError(
					"Unexpected exception occurred while launching Visual Studio Code.", false,
					null);
				return;
			}
		};

		new TaskBuilder("Opening File in VSCode", r)
				.setHasProgress(false)
				.setCanCancel(true)
				.launchModal();
		return;
	}

////////////////table stuff ////////////////// 

	private void configureTableColumns(TableChooserDialog tableDialog) {
		StringColumnDisplay fileNameColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Filename";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return ((LocalPathRowObject) rowObject).getFileName();
			}
		};

		ColumnDisplay<Integer> lineNumberColumn = new AbstractComparableColumnDisplay<>() {
			@Override
			public Integer getColumnValue(AddressableRowObject rowObject) {
				return ((LocalPathRowObject) rowObject).getLineNumber();
			}

			@Override
			public String getColumnName() {
				return "Line Number";
			}
		};

		StringColumnDisplay localPathColumn = new StringColumnDisplay() {

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return ((LocalPathRowObject) rowObject).getLocalPath();
			}

			@Override
			public String getColumnName() {
				return "Local Path";
			}

		};
		tableDialog.addCustomColumn(fileNameColumn);
		tableDialog.addCustomColumn(lineNumberColumn);
		tableDialog.addCustomColumn(localPathColumn);
	}

	class LocalPathRowObject implements AddressableRowObject {

		private Address baseAddress;
		private String fileName;
		private String localPath;
		private int lineNumber;

		LocalPathRowObject(SourceMapEntry entry) {
			this.baseAddress = entry.getBaseAddress();
			this.fileName = entry.getSourceFile().getFilename();
			this.lineNumber = entry.getLineNumber();
			this.localPath = pathTransformer.getTransformedPath(entry.getSourceFile(), true);
		}

		@Override
		public Address getAddress() {
			return baseAddress;
		}

		String getFileName() {
			return fileName;
		}

		String getLocalPath() {
			return localPath;
		}

		int getLineNumber() {
			return lineNumber;
		}
	}

	class OpenInIdeExecutor implements TableChooserExecutor {

		@Override
		public String getButtonName() {
			return "Open Source File";
		}

		@Override
		public boolean execute(AddressableRowObject rowObject) {
			LocalPathRowObject row = (LocalPathRowObject) rowObject;
			openInIde(row.getLocalPath(), row.getLineNumber());
			return false;
		}
	}

}
