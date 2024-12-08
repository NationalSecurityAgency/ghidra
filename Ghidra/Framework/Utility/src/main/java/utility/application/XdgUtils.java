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
package utility.application;

/**
 * Class to support the "XDG Base Directory Specification"
 * <p>
 * Based off version 0.8
 * 
 * @see <a href="https://specifications.freedesktop.org/basedir-spec/basedir-spec-0.8.html">basedir-spec-0.8.html</a> 
 */
public class XdgUtils {

	/**
	 * $XDG_DATA_HOME defines the base directory relative to which user-specific data files should 
	 * be stored. If $XDG_DATA_HOME is either not set or empty, a default equal to 
	 * $HOME/.local/share should be used.
	 */
	public static final String XDG_DATA_HOME = "XDG_DATA_HOME";

	/**
	 * $XDG_CONFIG_HOME defines the base directory relative to which user-specific configuration 
	 * files should be stored. If $XDG_CONFIG_HOME is either not set or empty, a default equal to 
	 * $HOME/.config should be used.
	 */
	public static final String XDG_CONFIG_HOME = "XDG_CONFIG_HOME";

	/**
	 * $XDG_STATE_HOME defines the base directory relative to which user-specific state files should
	 * be stored. If $XDG_STATE_HOME is either not set or empty, a default equal to 
	 * $HOME/.local/state should be used.
	 */
	public static final String XDG_STATE_HOME = "XDG_STATE_HOME";

	/**
	 * $XDG_DATA_DIRS defines the preference-ordered set of base directories to search for data 
	 * files in addition to the $XDG_DATA_HOME base directory. The directories in $XDG_DATA_DIRS 
	 * should be separated with a colon ':'.
	 */
	public static final String XDG_DATA_DIRS = "XDG_DATA_DIRS";

	/**
	 * $XDG_CONFIG_DIRS defines the preference-ordered set of base directories to search for 
	 * configuration files in addition to the $XDG_CONFIG_HOME base directory. The directories in 
	 * $XDG_CONFIG_DIRS should be separated with a colon ':'.
	 */
	public static final String XDG_CONFIG_DIRS = "XDG_CONFIG_DIRS";

	/**
	 * $XDG_CACHE_HOME defines the base directory relative to which user-specific non-essential 
	 * data files should be stored. If $XDG_CACHE_HOME is either not set or empty, a default equal 
	 * to $HOME/.cache should be used.
	 */
	public static final String XDG_CACHE_HOME = "XDG_CACHE_HOME";

	/**
	 * $XDG_RUNTIME_DIR defines the base directory relative to which user-specific non-essential 
	 * runtime files and other file objects (such as sockets, named pipes, ...) should be stored. 
	 * The directory MUST be owned by the user, and he MUST be the only one having read and write 
	 * access to it. Its Unix access mode MUST be 0700.
	 */
	public static final String XDG_RUNTIME_DIR = "XDG_RUNTIME_DIR";
}
