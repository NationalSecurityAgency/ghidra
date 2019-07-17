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
import java.util.Set;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class ClassDir {

	private String dirPath;
	private File dir;
	private ClassPackage classPackage;

	ClassDir(String dirPath, TaskMonitor monitor) throws CancelledException {
		this.dirPath = dirPath;
		this.dir = new File(dirPath);
		classPackage = new ClassPackage(dir, "", monitor);
	}

	void getClasses(Set<Class<?>> set, TaskMonitor monitor) throws CancelledException {
		classPackage.getClasses(set, monitor);
	}

	String getDirPath() {
		return dirPath;
	}

	@Override
	public String toString() {
		return dirPath;
	}
}
