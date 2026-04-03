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
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

/**
 * Class responsible for finding Java installations on an OpenBSD system.
 */
public class OpenBSDJavaFinder extends LinuxJavaFinder {

	@Override
	protected List<File> getJavaRootInstallDirs() {
		File localdir = new File("/usr/local");

		File[] filteredFiles = localdir.listFiles((dir, name) ->
        		name.toLowerCase().startsWith("jdk-")
		);

		return filteredFiles != null
			? new ArrayList<>(Arrays.asList(filteredFiles))
			: new ArrayList<>();
	}
}
