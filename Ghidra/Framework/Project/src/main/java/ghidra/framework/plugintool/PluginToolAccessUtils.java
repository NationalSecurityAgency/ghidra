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
package ghidra.framework.plugintool;

/**
 * Utility class to provide access to non-public methods on PluginTool. There are a number of
 * methods that internal classes need access to but we don't want on the public interface of
 * PluginTool.This is a stopgap approach until we clean up the package structure for tool related
 * classes and interfaces. This class should only be used by internal tool manager classes.
 */
public class PluginToolAccessUtils {

	private PluginToolAccessUtils() {
		// Can't be constructed
	}

	/**
	 * Disposes the tool.
	 * @param tool the tool to dispose
	 */
	public static void dispose(PluginTool tool) {
		tool.dispose();
	}

	/**
	 * Returns true if the tool can be closed. Note this does not handle any data saving. It only
	 * checks that there are no tasks running and the plugins can be closed.
	 * @param tool the tool to close
	 * @return true if the tool can be closed
	 */
	public static boolean canClose(PluginTool tool) {
		return tool.canStopTasks() && tool.canClosePlugins();
	}

}
