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
package ghidra.plugins.fsbrowser;

import java.util.*;

import javax.swing.Icon;

import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.Program;

/**
 * Represents a way to open a {@link DomainFile} in a {@link ProgramManager}
 */
public class OpenWithTarget {

	/**
	 * Returns a list of all running tools and tool templates that can be used to open a domainfile.
	 *  
	 * @return list of OpenWithTarget instances, maybe empty but not null
	 */
	public static List<OpenWithTarget> getAll() {
		List<OpenWithTarget> results = new ArrayList<>();
		Project project = AppInfo.getActiveProject();
		if (project != null) {
			results.addAll(getRunningTargets(project));

			ToolTemplate defaultTT = project.getToolServices()
					.getDefaultToolTemplate(ProgramContentHandler.PROGRAM_CONTENT_TYPE);
			results.add(new OpenWithTarget(defaultTT.getName(), null, defaultTT.getIcon()));

			ToolTemplate[] templates = project.getLocalToolChest().getToolTemplates();
			for (ToolTemplate toolTemplate : templates) {
				if (!toolTemplate.getName().equals(defaultTT.getName())) {
					results.add(
						new OpenWithTarget(toolTemplate.getName(), null, toolTemplate.getIcon()));
				}
			}
		}
		return results;
	}

	/**
	 * Returns an OpenWithTarget, or null, that represents the specified tool's default ability 
	 * to open a {@link DomainFile}.
	 * 
	 * @param tool a {@link PluginTool}
	 * @return a {@link OpenWithTarget}, or null if the specified tool can't open a domain file
	 */
	public static OpenWithTarget getDefault(PluginTool tool) {
		Project project = tool.getProject();
		if (project == null) {
			return null;
		}
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			return new OpenWithTarget(tool.getName(), pm, tool.getIcon());
		}
		if (AppInfo.getFrontEndTool().getDefaultLaunchMode() == DefaultLaunchMode.REUSE_TOOL) {
			List<OpenWithTarget> runningTargets = getRunningTargets(project);
			if (!runningTargets.isEmpty()) {
				return runningTargets.get(0);
			}
		}
		ToolTemplate defaultTT = project.getToolServices()
				.getDefaultToolTemplate(ProgramContentHandler.PROGRAM_CONTENT_TYPE);
		return new OpenWithTarget(defaultTT.getName(), null, defaultTT.getIcon());
	}

	/**
	 * Returns an OpenWithTarget, or null, that represents a running {@link ProgramManager}.
	 * 
	 * @param tool a {@link PluginTool}
	 * @return a {@link OpenWithTarget}, or null if there is no open {@link ProgramManager}
	 */
	public static OpenWithTarget getRunningProgramManager(PluginTool tool) {
		Project project = tool.getProject();
		if (project == null) {
			return null;
		}
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			return new OpenWithTarget(tool.getName(), pm, tool.getIcon());
		}
		List<OpenWithTarget> runningTargets = getRunningTargets(project);
		return !runningTargets.isEmpty() ? runningTargets.get(0) : null;
	}

	private final String name;
	private final ProgramManager pm;
	private final Icon icon;

	public OpenWithTarget(String name, ProgramManager pm, Icon icon) {
		this.name = name;
		this.pm = pm;
		this.icon = icon;
	}

	public String getName() {
		return name;
	}

	public ProgramManager getPm() {
		return pm;
	}

	public Icon getIcon() {
		return icon;
	}

	/**
	 * Opens the specified files, using whatever program manager / tool this instance represents.
	 * <p>
	 * The first item in the list of files will be focused / made visible, the other items in the
	 * list will be opened but not focused.
	 * 
	 * @param files {@link DomainFile}s  to open
	 */
	public void open(List<DomainFile> files) {
		Project project = AppInfo.getActiveProject();
		if (project == null) {
			return;
		}
		if (pm != null) {
			openWithPM(files);
		}
		else {
			openWithToolTemplate(project, files);
		}
	}

	private Map<DomainFile, Program> openWithPM(List<DomainFile> files) {
		Map<DomainFile, Program> results = new HashMap<>();
		for (DomainFile file : files) {
			int openMode =
				results.isEmpty() ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE;
			Program program = pm.openProgram(file, DomainFile.DEFAULT_VERSION, openMode);
			if (program != null) {
				results.put(file, program);
			}
		}
		return results;
	}

	private Map<DomainFile, Program> openWithToolTemplate(Project project, List<DomainFile> files) {
		Map<DomainFile, Program> results = new HashMap<>();

		PluginTool newTool = project.getToolServices().launchTool(name, files);

		ProgramManager newToolPM;
		if (newTool != null && (newToolPM = newTool.getService(ProgramManager.class)) != null) {
			Set<DomainFile> fileSet = new HashSet<>(files);
			for (Program openProgram : newToolPM.getAllOpenPrograms()) {
				if (fileSet.contains(openProgram.getDomainFile())) {
					results.put(openProgram.getDomainFile(), openProgram);
				}
			}
		}
		return results;
	}

	//----------------------------------------------------------------------------------------------

	private static List<OpenWithTarget> getRunningTargets(Project project) {
		List<OpenWithTarget> results = new ArrayList<>();
		for (PluginTool runningTool : project.getToolManager().getRunningTools()) {
			ProgramManager runningPM = runningTool.getService(ProgramManager.class);
			if (runningPM != null) {
				Program currentProgram = runningPM.getCurrentProgram();
				int programCount = runningPM.getAllOpenPrograms().length;
				String descName = runningTool.getName();
				if (currentProgram != null) {
					descName += ": " + currentProgram.getName();
					if (programCount > 1) {
						descName += " (+%d more)".formatted(programCount - 1);
					}
				}
				results.add(new OpenWithTarget(descName, runningPM, runningTool.getIcon()));
			}
		}
		Collections.sort(results, (r1, r2) -> r2.name.compareTo(r1.name));
		return results;
	}

}
