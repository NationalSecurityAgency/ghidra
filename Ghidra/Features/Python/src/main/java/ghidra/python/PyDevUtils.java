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
package ghidra.python;

import java.io.File;

import org.apache.commons.lang3.StringUtils;

public class PyDevUtils {

	public static final int PYDEV_REMOTE_DEBUGGER_PORT = 5678;

	/**
	 * Gets The PyDev source directory.
	 * 
	 * @return The PyDev source directory, or null if it not known.
	 */
	public static File getPyDevSrcDir() {
		String property = System.getProperty("eclipse.pysrc.dir");
		return StringUtils.isNotBlank(property) ? new File(property) : null;
	}

	/**
	 * Prevent instantiation of utility class.
	 */
	private PyDevUtils() {
	}
}
