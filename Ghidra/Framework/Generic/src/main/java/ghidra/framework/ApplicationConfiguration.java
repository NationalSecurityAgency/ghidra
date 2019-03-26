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
package ghidra.framework;

import java.io.File;

import ghidra.util.ConsoleErrorDisplay;
import ghidra.util.ErrorDisplay;
import ghidra.util.task.TaskMonitor;

public class ApplicationConfiguration {

	protected TaskMonitor monitor = TaskMonitor.DUMMY;
	protected boolean initializeLogging = true;
	protected File logFile;
	protected File scriptLogFile;

	/**
	 * For subclasses to do specific application initialization after all general application
	 * initialization occurs.
	 */
	protected void initializeApplication() {
		// Subclass overrides
	}

	/**
	 * Returns whether or not the application is headless.
	 * 
	 * @return true if the application is headless; otherwise, false.
	 */
	public boolean isHeadless() {
		return true;
	}

	/**
	 * Returns the currently set task monitor.
	 * 
	 * @return The currently set task monitor, which is by default a dummy monitor.
	 */
	public TaskMonitor getTaskMonitor() {
		return monitor;
	}

	/**
	 * Returns whether or not logging is to be initialized.
	 * 
	 * @return True if logging is to be initialized; otherwise, false.  This is true by default, 
	 * but may be set to false by the user.
	 * @see #setInitializeLogging
	 */
	public boolean isInitializeLogging() {
		return initializeLogging;
	}

	/**
	 * Returns the <b>user-defined</b> log file.
	 * 
	 * @return The <b>user-defined</b> log file. This is null by default and will only return a
	 * non-null value if it has been set by the user.
	 */
	public File getApplicationLogFile() {
		return logFile;
	}

	/**
	 * Sets a task monitor that will be called back with messages that report the status of the
	 * initialization process.
	 * 
	 * @param monitor The monitor to set.
	 */
	public void setTaskMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	public void setInitializeLogging(boolean initializeLogging) {
		this.initializeLogging = initializeLogging;
	}

	public void setApplicationLogFile(File logFile) {
		this.logFile = logFile;
	}

	/**
	 * Returns the <b>user-defined</b> script log file.
	 * 
	 * @return Returns the <b>user-defined</b> script log file.  This is null by default and will 
	 * only return a non-null value if it has been set by the user.
	 */
	public File getScriptLogFile() {
		return scriptLogFile;
	}

	public void setScriptLogFile(File scriptLogFile) {
		this.scriptLogFile = scriptLogFile;
	}

	public void installStaticFactories() {
		// nothing to install by default--can be overridden by subclasses
	}

	public ErrorDisplay getErrorDisplay() {
		return new ConsoleErrorDisplay();
	}
}
