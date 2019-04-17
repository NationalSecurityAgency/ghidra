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
package ghidra.app.services;

import java.io.File;
import java.util.Map;
import java.util.StringTokenizer;

import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.*;

public abstract class ProgramCoordinator {

	//TODO: Move this someplace appropriate

	private Program importProgram;
	private final Object importSemaphore = new Object();
	private boolean importTaskRunning;

	protected ProgramManager programManager;
	protected LanguageService languageService;

	public ProgramCoordinator(ProgramManager programManager, LanguageService languageService) {
		this.programManager = programManager;
		this.languageService = languageService;
	}

	public synchronized Program getProgram(String path, Address address) {
		Program program = findProgramInProgramManager(path, address);
		if (program == null) {
			program = findProgramInProject(path);
		}
		if (program == null) {
			program = importProgram(path);
		}
		return program;
	}

	protected Program findProgramInProgramManager(String path, Address address) {
		Program[] allOpenPrograms = programManager.getAllOpenPrograms();
		for (Program program : allOpenPrograms) {
			if (program.getExecutablePath().equalsIgnoreCase(path)) {
				if (program.getMemory().contains(address)) {
					return program;
				}
			}
		}
		return null;
	}

	abstract protected Program findProgramInProject(String path);

	protected Program findProgramInFolder(DomainFolder folder, String path) {
		DomainFolder[] subFolders = folder.getFolders();
		for (DomainFolder subFolder : subFolders) {
			Program p = findProgramInFolder(subFolder, path);
			if (p != null) {
				return p;
			}
		}
		DomainFile[] files = folder.getFiles();
		for (DomainFile file : files) {
			Map<String, String> metadata = file.getMetadata();
			String filePath = metadata.get("Executable Location");
			if (filePath == null) {
				continue;
			}
			if (filePath.equalsIgnoreCase(path)) {
				return programManager.openProgram(file);
			}
		}
		return null;
	}

	private Program importProgram(String executablePath) {
		importTaskRunning = false;
		importProgram = null;
		TaskLauncher.launch(new ImportTask(executablePath));
		try {
			//wait for at most 5 seconds for the import task to start
			int i = 0;
			while (!importTaskRunning && ++i < 50) {
				Thread.sleep(100);
			}
		}
		catch (Exception e) {
		}
		synchronized (importSemaphore) {
			return importProgram;
		}
	}

	private class ImportTask extends Task {
		private String executablePath;

		ImportTask(String executablePath) {
			super("Importing Program", true, false, true);
			this.executablePath = executablePath;
		}

		@Override
		public void run(TaskMonitor monitor) {
			importTaskRunning = true;
			synchronized (importSemaphore) {
				File file = new File(executablePath);
				Object consumer = this;
				MessageLog messageLog = new MessageLog();
				DomainFolder folder = getFolder(file.getParent());
				Class<? extends Loader> loaderClass = PeLoader.class;
				try {
					Language language = languageService.getDefaultLanguage(
						Processor.findOrPossiblyCreateProcessor("x86"));
					CompilerSpec compilerSpec =
						language.getCompilerSpecByID(new CompilerSpecID("windows"));
					importProgram = AutoImporter.importByUsingSpecificLoaderClassAndLcs(file,
						folder, loaderClass, null, language, compilerSpec, consumer, messageLog,
						monitor);
					programManager.openProgram(importProgram);
					importProgram.release(this);
				}
				catch (Exception e) {
					e.printStackTrace();//TODO
				}
				finally {
					importSemaphore.notify();
				}
			}
		}
	}

	private DomainFolder getFolder(String executablePath) {
		StringTokenizer tokenizer = new StringTokenizer(executablePath, ":/\\");
		Project project = AppInfo.getActiveProject();
		ProjectData projectData = project.getProjectData();
		DomainFolder folder = projectData.getRootFolder();
		folder = createOrGetFolder(folder, getPrivateRoot());
		while (tokenizer.hasMoreTokens()) {
			String pathElement = tokenizer.nextToken();

			folder = createOrGetFolder(folder, pathElement);
		}
		return folder;
	}

	private DomainFolder createOrGetFolder(DomainFolder parent, String folderName) {
		DomainFolder folder = parent.getFolder(folderName);
		if (folder == null) {
			try {
				folder = parent.createFolder(folderName);
			}
			catch (Exception e) {
				folder = parent;
			}
		}
		return folder;
	}

	abstract protected String getPrivateRoot();
}
