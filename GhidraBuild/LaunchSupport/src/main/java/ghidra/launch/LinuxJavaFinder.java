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
package ghidra.launch;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Class responsible for finding Java installations on a Linux system.
 */
public class LinuxJavaFinder extends JavaFinder {

	@Override
	protected List<File> getJavaRootInstallDirs() {
		List<File> javaRootInstallDirs = new ArrayList<>();
		javaRootInstallDirs.add(new File("/usr/lib/jvm"));
		return javaRootInstallDirs;
	}

	@Override
	protected String getJavaHomeSubDirPath() {
		return "";
	}

	@Override
	protected File getJreHomeFromJavaHome(File javaHomeDir) {
		if (javaHomeDir.isDirectory() && !javaHomeDir.getName().equals("jre")) {
			for (File dir : javaHomeDir.listFiles()) {
				if (dir.isDirectory() && dir.getName().equals("jre")) {
					return dir;
				}
			}
		}
		return javaHomeDir;
	}

	@Override
	protected File getJdkHomeFromJavaHome(File javaHomeDir) {
		if (javaHomeDir.getName().equals("jre")) {
			return javaHomeDir.getParentFile();
		}
		return javaHomeDir;
	}
}
