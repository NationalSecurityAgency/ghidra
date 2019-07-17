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
package ghidra.plugins.fsbrowser.tasks;

import java.io.IOException;
import java.util.List;

import ghidra.app.services.ProgramManager;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectDataUtils;
import ghidra.framework.plugintool.Plugin;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugin.importer.ProgramMappingService;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class GFileSystemLoadKernelTask extends Task {
	private List<FSRL> fileList;
	private ProgramManager programManager;

	public GFileSystemLoadKernelTask(Plugin plugin, ProgramManager programManager,
			List<FSRL> fileList) {
		super("Loading iOS kernel...", true, true, true);
		this.programManager = programManager;
		this.fileList = fileList;
	}

	@Override
	public void run(TaskMonitor monitor) {
		if (fileList.isEmpty()) {
			Msg.showWarn(this, null, "Load Kernel Task Error", "Nothing to do");
			return;
		}
		if (!FSUtilities.isSameFS(fileList)) {
			Msg.showError(this, null, "Load Kernel Task Error",
				"The list of files to import must be from the same filesystem");
			return;
		}
		FSRL firstFSRL = fileList.get(0);
		try (RefdFile firstFile = FileSystemService.getInstance().getRefdFile(firstFSRL, monitor)) {
			GFileSystem fs = firstFile.fsRef.getFilesystem();

			String containerName = fs.getFSRL().getContainer().getName();
			monitor.setMessage("Loading iOS Kernel from " + containerName + "...");
			for (FSRL fsrl : fileList) {
				if (monitor.isCancelled()) {
					break;
				}
				GFile file = firstFile.fsRef.getFilesystem().lookup(fsrl.getPath());
				process(file, monitor);

			}
		}
		catch (UnsupportedOperationException | IOException | CancelledException e) {
			Msg.showError(this, null, "Error extracting file", e.getMessage(), e);
		}
	}

	private void process(GFile file, TaskMonitor monitor) throws IOException {

		if (isSpecialDirectory(file)) {
			return;
		}

		if (file.isDirectory() &&
			!((GFileSystemProgramProvider) file.getFilesystem()).canProvideProgram(file)) {
			List<GFile> listing = file.getFilesystem().getListing(file);
			for (GFile child : listing) {
				if (monitor.isCancelled()) {
					break;
				}
				process(child, monitor);
			}
		}
		else {
			try {
				loadKext(file, monitor);
			}
			catch (Exception e) {
				Msg.warn(this, "unable to load kext file: " + file.getName(), e);
			}
		}
	}

	private boolean isSpecialDirectory(GFile directory2) {
		return false;
	}

	private void loadKext(GFile file, TaskMonitor monitor) throws Exception {
		if (file.getLength() == 0) {
			return;
		}
		if (!file.getName().endsWith(".kext")) {
			return;
		}
		monitor.setMessage("Opening " + file.getName());

		Program program = ProgramMappingService.findMatchingProgramOpenIfNeeded(file.getFSRL(),
			this, programManager, ProgramManager.OPEN_VISIBLE);
		if (program != null) {
			program.release(this);
			return;
		}

		//File cacheFile = FileSystemService.getInstance().getFile(file.getFSRL(), monitor);

		if (file.getFilesystem() instanceof GFileSystemProgramProvider) {
			LanguageService languageService = DefaultLanguageService.getLanguageService();

			GFileSystemProgramProvider fileSystem =
				(GFileSystemProgramProvider) file.getFilesystem();
			program = fileSystem.getProgram(file, languageService, monitor, this);
		}

		if (program != null) {
			try {
				DomainFolder folder = ProjectDataUtils.createDomainFolderPath(
					AppInfo.getActiveProject().getProjectData().getRootFolder(),
					file.getParentFile().getPath());
				String fileName = ProjectDataUtils.getUniqueName(folder, program.getName());

				GhidraProgramUtilities.setAnalyzedFlag(program, true);
				ImporterUtilities.setProgramProperties(program, file.getFSRL(), monitor);

				folder.createFile(fileName, program, monitor);

				programManager.openProgram(program);
				ProgramMappingService.createAssociation(file.getFSRL(), program);
			}
			finally {
				program.release(this);
			}
		}
	}
}
