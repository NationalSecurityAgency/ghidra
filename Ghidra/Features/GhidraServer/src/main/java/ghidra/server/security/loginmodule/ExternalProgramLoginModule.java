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
package ghidra.server.security.loginmodule;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import com.sun.security.auth.UserPrincipal;

import generic.concurrent.io.ProcessConsumer;
import ghidra.server.RepositoryManager;
import ghidra.util.DateUtils;
import ghidra.util.timer.Watchdog;

/**
 * A JAAS {@link LoginModule} that executes an external program that decides if the username
 * and password are authorized.
 * <p>
 * Compatible with Apache's mod_authnz_external.
 * <p>
 * JAAS will create a new instance of this class for each login operation.
 * <p>
 * The options for this module (the path to the external program, timeout values, etc)
 * are supplied to the {@link #initialize(Subject, CallbackHandler, Map, Map)}
 * by JAAS and are typically read from a config file that looks like:
 * <pre>
 * auth {
 * 	ghidra.server.security.loginmodule.ExternalProgramLoginModule required
 * 		PROGRAM="jaas_external_program.example.sh"
 * 		ARG_00="arg1" ARG_01="test arg2"
 * 		TIMEOUT="1000"
 * 		USER_PROMPT="Enter username"
 * 		PASSWORD_PROMPT="Enter password"
 * 	;
 * };
 * </pre>
 * <p>
 * The external program is fed the username\n and password\n on its STDIN (ie. two text lines).
 * The external authenticator needs to exit with 0 (zero) error level
 * if the authentication was successful, or a non-zero error level if not successful.
 * <p>
 * This implementation tries to follow best practices for JAAS LoginModules, even
 * though Ghidra does not utilize the entire API.
 * <p>
 * For instance, Ghidra will override JAAS LoginModule's prompt values for name and password.
 * <p>
 * Options:
 * <ul>
 * 	<li>PROGRAM - path to an executable program or script.</li>
 * 	<li>ARG_* - any number of arguments to be passed to the program.<br>
 * 	Example: ARG_00="foo" ARG_01="bar".  Arguments are ordered according to their natural
 *  sorting order, so it is advisable to keep the suffixes to the same length.</li>
 *  <li>TIMEOUT - number of milliseconds to wait for the external program to return results</li>
 *  <li>USER_PROMPT - a string to send to the user to prompt them to type their name (not used in Ghidra)</li>
 *  <li>PASSWORD_PROMPT - a string to send to the user to prompt them to type their password (not used in Ghidra)</li>
 * </ul>
 *
 */
public class ExternalProgramLoginModule implements LoginModule {
//	private static final String USERNAME_KEY = "javax.security.auth.login.name";
//	private static final String PASSWORD_KEY = "javax.security.auth.login.password";
	private static final String USER_PROMPT_OPTION_NAME = "USER_PROMPT";
	private static final String PASSWORD_PROMPT_OPTION_NAME = "PASSWORD_PROMPT";
	private static final String TIMEOUT_OPTION_NAME = "TIMEOUT";
	private static final String PROGRAM_OPTION_NAME = "PROGRAM";
	private static final String ARG_OPTION_NAME = "ARG_";
	private static final long DEFAULT_TIMEOUT_MS = DateUtils.MS_PER_SEC * 10;

	private Subject subject;
	private CallbackHandler callbackHandler;
	//private Map<String, Object> sharedState;
	private Map<String, Object> options;
	//private boolean useSharedState;
	//private boolean clearSharedCreds;
	private UserPrincipal user;
	private String username;
	private char[] password;
	private String[] cmdArray;
	private String extProgramName;
	private boolean success;
	private boolean committed;
	private long timeout_ms = DEFAULT_TIMEOUT_MS;

	@SuppressWarnings("unchecked")
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		//this.sharedState = (Map<String, Object>) sharedState;
		this.options = (Map<String, Object>) options;
	}

	@Override
	public boolean login() throws LoginException {
		readOptions();
		getNameAndPassword();
		callExternalProgram();
		success = true;
		user = new UserPrincipal(username);
		return true;
	}

	@Override
	public boolean commit() throws LoginException {
		if (!success) {
			return false;
		}
		if (!subject.isReadOnly()) {
			if (!user.implies(subject)) {
				subject.getPrincipals().add(user);
			}
		}
		committed = true;
		return true;
	}

	@Override
	public boolean abort() throws LoginException {
		if (!success) {
			return false;
		}
		if (!committed) {
			success = false;
			cleanup();
		}
		else {
			logout();
		}
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		if (subject.isReadOnly()) {
			cleanup();
			throw new LoginException("Subject is read-only");
		}
		subject.getPrincipals().remove(user);

		cleanup();
		success = false;
		committed = false;

		return true;
	}

	private void cleanup() {
		user = null;
		username = null;
		if (password != null) {
			Arrays.fill(password, '\0');
			password = null;
		}
		/* not impl yet
		if (clearSharedCreds) {
			sharedState.remove(USERNAME_KEY);
			sharedState.remove(PASSWORD_KEY);
		} */
	}

	private void readOptions() throws LoginException {
		String timeoutStr = (String) options.get(TIMEOUT_OPTION_NAME);
		if (timeoutStr != null) {
			try {
				timeout_ms = Long.parseLong(timeoutStr);
			}
			catch (NumberFormatException e) {
				// ignore, leave timeout at default 10sec
			}
		}
		readExtProgOptions();
	}

	private void callExternalProgram() throws LoginException {

		AtomicReference<Process> process = new AtomicReference<>();

		try (Watchdog watchdog = new Watchdog(timeout_ms, () -> {
			Process local_p = process.get();
			if (local_p != null) {
				local_p.destroyForcibly();
			}
		})) {
			watchdog.arm();
			Process p = Runtime.getRuntime().exec(cmdArray);
			process.set(p);

			ProcessConsumer.consume(p.getInputStream(), stdOutStr -> {
				RepositoryManager.log(null, null, extProgramName + " STDOUT: " + stdOutStr, null);
			});

			ProcessConsumer.consume(p.getErrorStream(), errStr -> {
				RepositoryManager.log(null, null, extProgramName + " STDERR: " + errStr, null);
			});

			PrintWriter outputWriter = new PrintWriter(p.getOutputStream());
			outputWriter.write(username);
			outputWriter.write("\n");
			outputWriter.write(password);
			outputWriter.write("\n");
			outputWriter.flush();

			int exitValue = p.waitFor();
			if (exitValue != 0) {
				throw new FailedLoginException(
					"Login failed: external command exited with error " + exitValue);
			}
		}
		catch (IOException | InterruptedException e) {
			RepositoryManager.log(null, null,
				"Exception when executing " + extProgramName + ":" + e.getMessage(), null);
			throw new LoginException("Error executing external program");
		}
		finally {
			Arrays.fill(password, '\0');
			password = null;
			Process p = process.get();
			if (p != null && p.isAlive()) {
				if (p.isAlive()) {
					try {
						p.waitFor(timeout_ms, TimeUnit.MILLISECONDS);
					}
					catch (InterruptedException e) {
						// ignore
					}
					finally {
						p.destroyForcibly();
					}
				}
			}
		}
	}

	private void readExtProgOptions() throws LoginException {
		String externalProgram = (String) options.get(PROGRAM_OPTION_NAME);
		if (externalProgram == null || externalProgram.isBlank()) {
			throw new LoginException(
				"Missing " + PROGRAM_OPTION_NAME + "=path_to_external_program in options");
		}
		File extProFile = new File(externalProgram).getAbsoluteFile();
		if (!extProFile.exists()) {
			throw new LoginException(
				"Bad " + PROGRAM_OPTION_NAME + "=path_to_external_program in options");
		}
		extProgramName = extProFile.getName();

		List<String> argKeys = options.keySet()
				.stream()
				.filter(
					key -> key.startsWith(ARG_OPTION_NAME))
				.sorted()
				.collect(Collectors.toList());
		List<String> cmdArrayValues = new ArrayList<>();
		cmdArrayValues.add(externalProgram.toString());
		for (String argKey : argKeys) {
			String val = options.get(argKey).toString();
			cmdArrayValues.add(val);
		}
		cmdArray = cmdArrayValues.toArray(new String[cmdArrayValues.size()]);
	}

	private void getNameAndPassword() throws LoginException {
		String userPrompt = options.getOrDefault(USER_PROMPT_OPTION_NAME, "User name").toString();
		String passPrompt =
			options.getOrDefault(PASSWORD_PROMPT_OPTION_NAME, "Password").toString();

		List<Callback> callbacks = new ArrayList<>();
		NameCallback ncb = null;
		PasswordCallback pcb = null;

		/* not impl yet
		if (useSharedState) {
			username = (String) sharedState.get(USERNAME_KEY);
			password = (char[]) sharedState.get(PASSWORD_KEY);
			if (password != null) {
				password = password.clone();
			}
		} */

		if (username == null) {
			ncb = new NameCallback(userPrompt);
			callbacks.add(ncb);
		}
		if (password == null) {
			pcb = new PasswordCallback(passPrompt, false);
			callbacks.add(pcb);
		}

		if (!callbacks.isEmpty()) {
			try {
				callbackHandler.handle(callbacks.toArray(new Callback[callbacks.size()]));
				if (ncb != null) {
					username = ncb.getName();
				}
				if (pcb != null) {
					password = pcb.getPassword();
					pcb.clearPassword();
				}

				if (username == null || password == null) {
					throw new LoginException("Failed to get username or password");
				}
			}
			catch (IOException | UnsupportedCallbackException e) {
				throw new LoginException("Error during callback: " + e.getMessage());
			}
		}
		validateUsernameAndPasswordFormat();
	}

	private void validateUsernameAndPasswordFormat() throws LoginException {
		if (username.contains("\n") || username.contains("\0")) {
			throw new LoginException("Bad characters in username");
		}
		String tmpPass = String.valueOf(password);
		if (tmpPass.contains("\n") || tmpPass.contains("\0")) {
			throw new LoginException("Bad characters in password");
		}
	}

}
