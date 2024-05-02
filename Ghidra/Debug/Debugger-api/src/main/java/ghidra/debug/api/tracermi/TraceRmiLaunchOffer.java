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
package ghidra.debug.api.tracermi;

import java.util.List;
import java.util.Map;

import javax.swing.Icon;

import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

/**
 * An offer to launch a program with a given mechanism
 * 
 * <p>
 * Typically each offer is configured with the program it's going to launch, and knows how to work a
 * specific connector and platform to obtain a target executing the program's image. The mechanisms
 * may vary wildly from platform to platform.
 */
public interface TraceRmiLaunchOffer {

	/**
	 * The result of launching a program
	 * 
	 * <p>
	 * The launch may not always be completely successful. Instead of tearing things down, partial
	 * launches are left in place, in case the user wishes to repair/complete the steps manually. If
	 * the result includes a connection, then at least that was successful. If not, then the caller
	 * can choose how to treat the terminal sessions. If the cause of failure was an exception, it
	 * is included. If the launch succeeded, but module mapping failed, the result will include a
	 * trace and the exception. If an error occurred in the shell script, it may not be communicated
	 * here, but instead displayed only in the terminal.
	 * 
	 * @param program the program associated with the launch attempt
	 * @param sessions any terminal sessions created while launching the back-end. If there are more
	 *            than one, they are distinguished by launcher-defined keys. If there are no
	 *            sessions, then there was likely a catastrophic error in the launcher.
	 * @param acceptor the acceptor if waiting for a connection
	 * @param connection if the target connected back to Ghidra, that connection
	 * @param trace if the connection started a trace, the (first) trace it created
	 * @param exception optional error, if failed
	 */
	public record LaunchResult(Program program, Map<String, TerminalSession> sessions,
			TraceRmiAcceptor acceptor, TraceRmiConnection connection, Trace trace,
			Throwable exception) implements AutoCloseable {
		public LaunchResult(Program program, Map<String, TerminalSession> sessions,
				TraceRmiAcceptor acceptor, TraceRmiConnection connection, Trace trace,
				Throwable exception) {
			this.program = program;
			this.sessions = sessions;
			this.acceptor = acceptor == null || acceptor.isClosed() ? null : acceptor;
			this.connection = connection;
			this.trace = trace;
			this.exception = exception;
		}

		@Override
		public void close() throws Exception {
			if (connection != null) {
				connection.close();
			}
			if (acceptor != null) {
				acceptor.cancel();
			}
			for (TerminalSession s : sessions.values()) {
				s.close();
			}
		}
	}

	/**
	 * When programmatically customizing launch configuration, describes callback timing relative to
	 * prompting the user.
	 */
	public enum RelPrompt {
		/**
		 * The user is not prompted for parameters. This will be the only callback.
		 */
		NONE,
		/**
		 * The user will be prompted. This callback can pre-populate suggested parameters. Another
		 * callback will be issued if the user does not cancel.
		 */
		BEFORE,
		/**
		 * The user has confirmed the parameters. This callback can validate or override the users
		 * parameters. Overriding the user is discouraged. This is the final callback.
		 */
		AFTER;
	}

	public enum PromptMode {
		/**
		 * The user is always prompted for parameters.
		 */
		ALWAYS,
		/**
		 * The user is never prompted for parameters.
		 */
		NEVER,
		/**
		 * The user is prompted after an error.
		 */
		ON_ERROR;
	}

	/**
	 * Callbacks for custom configuration when launching a program
	 */
	public interface LaunchConfigurator {
		LaunchConfigurator NOP = new LaunchConfigurator() {};

		/**
		 * Determine whether the user should be prompted to confirm launch parameters
		 * 
		 * @return the prompt mode
		 */
		default PromptMode getPromptMode() {
			return PromptMode.NEVER;
		}

		/**
		 * Re-write the launcher arguments, if desired
		 * 
		 * @param offer the offer that will create the target
		 * @param arguments the arguments suggested by the offer or saved settings
		 * @param relPrompt describes the timing of this callback relative to prompting the user
		 * @return the adjusted arguments
		 */
		default Map<String, ?> configureLauncher(TraceRmiLaunchOffer offer,
				Map<String, ?> arguments, RelPrompt relPrompt) {
			return arguments;
		}
	}

	/**
	 * Launch the program using the offered mechanism
	 * 
	 * @param monitor a monitor for progress and cancellation
	 * @param configurator the configuration callback
	 * @return the launch result
	 */
	LaunchResult launchProgram(TaskMonitor monitor, LaunchConfigurator configurator);

	/**
	 * Launch the program using the offered mechanism
	 * 
	 * @param monitor a monitor for progress and cancellation
	 * @return the launch result
	 */
	default LaunchResult launchProgram(TaskMonitor monitor) {
		return launchProgram(monitor, LaunchConfigurator.NOP);
	}

	/**
	 * A name so that this offer can be recognized later
	 * 
	 * <p>
	 * The name is saved to configuration files, so that user preferences and priorities can be
	 * memorized. The opinion will generate each offer fresh each time, so it's important that the
	 * "same offer" have the same configuration name. Note that the name <em>cannot</em> depend on
	 * the program name, but can depend on the model factory and program language and/or compiler
	 * spec. This name cannot contain semicolons ({@code ;}).
	 * 
	 * @return the configuration name
	 */
	String getConfigName();

	/**
	 * Get the icon displayed in the UI for this offer
	 * 
	 * <p>
	 * Please take care when overriding this that the icon still clearly indicates the target will
	 * be executed. Changing it, e.g., to the same icon as "Step" would be an unwelcome prank. A
	 * more reasonable choice would be the standard {@code "icon.debugger"} plus an overlay, or the
	 * branding of the underlying technology, e.g., QEMU or GDB.
	 * 
	 * @return the icon
	 */
	Icon getIcon();

	/**
	 * Get the menu path subordinate to "Debugger.Debug [imagePath]" for this offer.
	 * 
	 * <p>
	 * By default, this is just the title, i.e., the same as in the quick-launch drop-down menu. A
	 * package that introduces a large number of offers should override this method to organize
	 * them. A general rule of thumb is "no more than seven." Except at the level immediately under
	 * "Debug [imagePath]," no more than seven items should be presented to the user. In some cases,
	 * it may be more appropriate to group things using {@link #getMenuGroup() menu groups} rather
	 * than sub menus.
	 * 
	 * <p>
	 * Organization is very much a matter of taste, but consider that you are cooperating with other
	 * packages to populate the launcher menu. The top level is especially contentious, but sub
	 * menus, if named appropriately, are presumed to belong to a single package.
	 * 
	 * @return the path
	 */
	default List<String> getMenuPath() {
		return List.of(getTitle());
	}

	/**
	 * Get the text displayed in the quick-launch drop-down menu.
	 * 
	 * <p>
	 * No two offers should ever have the same title, even if they appear in different sub-menus.
	 * Otherwise, the user cannot distinguish the offers in the quick-launch drop-down menu.
	 * 
	 * @return the menu title
	 */
	public String getTitle();

	/**
	 * Get an HTML description of the connector
	 * 
	 * @return the description
	 */
	public String getDescription();

	/**
	 * Get the menu group for the offer
	 * 
	 * <p>
	 * Especially for entries immediately under to "Debugger.Debug [imagePath]", specifies the menu
	 * group. A package that introduces a large number of offers should instead consider
	 * {@link #getMenuPath() sub menus}.
	 * 
	 * @return the menu group
	 */
	default String getMenuGroup() {
		return "";
	}

	/**
	 * Controls the position in the menu (within its group) of the entry
	 * 
	 * <p>
	 * The menus will always be presented in the same order, barring any changes to the plugins or
	 * launcher properties. Groups are alphabetized and visually separated. Then sub groups are
	 * alphabetized, but <em>not</em> visually separated. Finally, offers are alphabetized by their
	 * final path element, usually the title.
	 * 
	 * <p>
	 * The order of entries in the quick-launch drop-down menu is always most-recently to
	 * least-recently used. An entry that has never been used does not appear in the quick launch
	 * menu.
	 * 
	 * @return the sub-group name for ordering in the menu
	 */
	default String getMenuOrder() {
		return "";
	}

	/**
	 * Get the location for additional help about this specific offer
	 * 
	 * <p>
	 * The default is just the entry on Trace RMI launchers in general.
	 * 
	 * @return the location
	 */
	default HelpLocation getHelpLocation() {
		return new HelpLocation("TraceRmiPlugin", "launch");
	}

	/**
	 * Get the parameter descriptions for the launcher
	 * 
	 * @return the parameters
	 */
	Map<String, ParameterDescription<?>> getParameters();

	/**
	 * Check if this offer requires an open program
	 * 
	 * @return true if required
	 */
	boolean requiresImage();
}
