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
package ghidradev.ghidrasymbollookup.utils;

import java.util.*;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.CoreException;

import ghidradev.EclipseMessageUtils;

/**
 * Utility methods for interacting with CDT.
 */
public class CdtUtils {

	/**
	 * CDT C nature.
	 */
	public static final String C_NATURE = "org.eclipse.cdt.core.cnature";

	/**
	 * CDT C++ nature.
	 */
	public static final String CC_NATURE = "org.eclipse.cdt.core.ccnature";
	
	/**
	 * Gets all of the open CDT projects in the workspace.
	 * 
	 * @return A collection of the open CDT projects in the workspace.
	 */
	public static Collection<IProject> getCDTProjects() {
		List<IProject> cdtProjects = new ArrayList<>();
		for (IProject project : ResourcesPlugin.getWorkspace().getRoot().getProjects()) {
			if (project.isOpen() && isCdtProject(project)) {
				cdtProjects.add(project);
			}
		}
		return cdtProjects;
	}

	/**
	 * Checks to see if the given project is a CDT project.
	 * 
	 * @param project The project to check.
	 * @return True if the given project is a CDT project; otherwise, false.
	 */
	public static boolean isCdtProject(IProject project) {
		try {
			return project != null && (project.hasNature(C_NATURE) || project.hasNature(CC_NATURE));
		}
		catch (CoreException e) {
			EclipseMessageUtils.error("CDT project check failed", e);
			return false;
		}
	}

}
