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
import java.io.File;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;

public class PopulateBigRepoScript extends GhidraScript {

	private static final File TEST_BINARY = new File("/tmp/helloWorld");

	@Override
	protected void run() throws Exception {

		Project project = state.getProject();
		ProjectData projectData = project.getProjectData();

		DomainFile firstFile = getFirstFile(projectData);

		for (int i = 1; i < 200000; i++) {
			String path = getFolderPath(i);
			DomainFolder folder = projectData.getRootFolder();
			String[] splitPath = path.split("/");
			for (int n = 1; n < splitPath.length; n++) {
				DomainFolder subfolder = folder.getFolder(splitPath[n]);
				if (subfolder == null) {
					subfolder = folder.createFolder(splitPath[n]);
				}
				folder = subfolder;
			}

			String name = getName(i);
			if (folder.getFile(name) == null) {
				DomainFile newFile = firstFile.copyTo(folder, monitor);
				newFile = newFile.setName(name);
				newFile.addToVersionControl("Initial", false, monitor);
				System.out.println("File: " + i + " - " + newFile.getPathname());
			}
		}
	}

	private DomainFile getFirstFile(ProjectData projectData) throws Exception {
		DomainFolder folder = projectData.getFolder(getFolderPath(0));
		String name = getName(0);

		DomainFile df = folder.getFile(name);
		if (df != null) {
			return df;
		}
		Program p = importFile(TEST_BINARY);
		try {
			df = folder.createFile(name, p, monitor);
		}
		finally {
			p.release(this);
		}

		df.addToVersionControl("Initial", false, monitor);

		return df;
	}

	private Integer[] getPath(int counter) {
		if (counter == 0) {
			return new Integer[] { 0 };
		}
		ArrayList<Integer> list = new ArrayList<>();
		while (counter != 0) {
			int n = counter % 10;
			counter = counter / 10;
			list.add(n);
		}
		Integer[] a = new Integer[list.size()];
		int i = a.length;
		for (Integer n : list) { // fip path with file# last instead of first
			a[--i] = n;
		}
		return a;
	}

	private String getName(int counter) {
		Integer[] path = getPath(counter);
		StringBuilder buf = new StringBuilder("df");
		for (int n : path) {
			buf.append(n);
		}
		return buf.toString();
	}

	private String getFolderPath(int counter) {
		Integer[] path = getPath(counter);
		StringBuilder buf = new StringBuilder("/");
		for (int i = 0; i < (path.length - 1); i++) {
			buf.append(path[i]);
			buf.append("/");
		}
		return buf.toString();
	}

}
