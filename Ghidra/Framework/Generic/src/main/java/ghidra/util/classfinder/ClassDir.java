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
package ghidra.util.classfinder;

import java.io.File;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class ClassDir extends ClassLocation {

	private String dirPath;
	private File dir;
	private ClassPackage classPackage;

	ClassDir(String dirPath, List<ClassFileInfo> dest, TaskMonitor monitor) {
		super(dest);
		this.dirPath = dirPath;
		this.dir = new File(dirPath);
		this.classPackage = new ClassPackage(dir, "", dest, monitor);
		start(monitor);
	}

	@Override
	protected void scan(TaskMonitor monitor) throws CancelledException {
		classPackage.start(monitor);
		classPackage.join(monitor);
	}

	String getDirPath() {
		return dirPath;
	}

	@Override
	public String toString() {
		return dirPath;
	}
}
