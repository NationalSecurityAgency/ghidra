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
package ghidra.pty;

import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;

public class ShellUtils {
	enum State {
		NORMAL, NORMAL_ESCAPE, DQUOTE, DQUOTE_ESCAPE, SQUOTE, SQUOTE_ESCAPE;
	}

	/**
	 * Parse a command line into an argument list
	 * <p>
	 * LATER: This is meant to mimic UNIX- / C-style arguments, but that's probably not appropriate
	 * on all systems. We should either:
	 * 
	 * <ol>
	 * <li>Let the offer specify how <code>@args</code> ought to be treated.</li>
	 * <li>Let the header annotations for <code>@args</code> include some extra specifier.</li>
	 * </ol>
	 * 
	 * @param args the arguments as a single string
	 * @return the list of split arguments
	 */
	public static List<String> parseArgs(String args) {
		List<String> argsList = new ArrayList<>();
		StringBuilder curArg = new StringBuilder();
		State state = State.NORMAL;
		for (int i = 0; i < args.length(); i++) {
			char c = args.charAt(i);
			switch (state) {
				case NORMAL:
					switch (c) {
						case '\\':
							state = State.NORMAL_ESCAPE;
							break;
						case '"':
							state = State.DQUOTE;
							break;
						case '\'':
							state = State.SQUOTE;
							break;
						case ' ':
							argsList.add(curArg.toString());
							curArg.setLength(0);
							break;
						default:
							curArg.append(c);
					}
					break;
				case NORMAL_ESCAPE:
					curArg.append(c);
					state = State.NORMAL;
					break;
				case DQUOTE:
					switch (c) {
						case '\\':
							state = State.DQUOTE_ESCAPE;
							break;
						case '"':
							state = State.NORMAL;
							break;
						default:
							curArg.append(c);
					}
					break;
				case DQUOTE_ESCAPE:
					curArg.append(c);
					state = State.DQUOTE;
					break;
				case SQUOTE:
					switch (c) {
						case '\\':
							state = State.SQUOTE_ESCAPE;
							break;
						case '\'':
							state = State.NORMAL;
							break;
						default:
							curArg.append(c);
					}
					break;
				case SQUOTE_ESCAPE:
					curArg.append(c);
					state = State.SQUOTE;
					break;
				default:
					throw new AssertionError("Shouldn't be here!");
			}
		}
		switch (state) {
			case NORMAL:
				if (curArg.length() != 0) {
					argsList.add(curArg.toString());
				}
				break;
			case DQUOTE:
			case SQUOTE:
				throw new IllegalArgumentException("Unterminated string");
			case NORMAL_ESCAPE:
			case DQUOTE_ESCAPE:
			case SQUOTE_ESCAPE:
				throw new IllegalArgumentException("Incomplete escaped character");
			default:
				throw new AssertionError("Shouldn't be here!");

		}
		return argsList;
	}

	public static String removePath(String exec) {
		return Paths.get(exec).getFileName().toString();
	}

	public static List<String> removePath(List<String> args) {
		if (args.isEmpty()) {
			return List.of();
		}
		List<String> copy = new ArrayList<>(args);
		copy.set(0, removePath(args.get(0)));
		return List.copyOf(copy);
	}

	public static String generateLine(List<String> args, Shell shell) {
		if (args.isEmpty()) {
			return "";
		}
		StringBuilder line = new StringBuilder(shell.generateArgument(args.get(0)));
		for (int i = 1; i < args.size(); i++) {
			String a = args.get(i);
			line.append(" " + shell.generateArgument(a));
		}
		return line.toString();
	}

	/**
	 * A target shell for command-line arguments
	 * <p>
	 * This determines how arguments are quoted and/or escaped. This should be set based on the
	 * shell that is going to receive the actual commands, which may or may not be the local shell.
	 * In many cases, it is the local shell, but please ensure for remote cases, the correct shell
	 * is specified.
	 */
	public enum Shell {
		/**
		 * For display purposes only. DO NOT pass to any actual shell.
		 */
		DISPLAY {
			@Override
			public String generateArgument(String a) {
				if (a.contains(" ")) {
					if (a.contains("\"")) {
						if (a.contains("'")) {
							return '"' + a.replace("\"", "\\\"") + '"';
						}
						return "'" + a + "'";
					}
					return '"' + a + '"';
				}
				return a;
			}
		},
		/**
		 * Unix shells that follow the same conventions as "sh". This is most Unix shells.
		 */
		UNIX_SH {
			@Override
			public String generateArgument(String a) {
				StringBuilder b = new StringBuilder();
				for (int i = 0; i < a.length(); i++) {
					char c = a.charAt(i);
					boolean esc = switch (c) {
						case '\t', ' ', // Whitespace
								'&', '|', ';', '`', '(', ')', // Syntax, command separators
								'<', '>', // Redirection
								'$', // Variable substitution
								'#', // Comments
								'[', ']', '?', '*', // File globbing
								'"', '\'', // Quotes
								'\\' // The escape character itself
								-> true;
						default -> false;
					};
					if (esc) {
						b.append('\\');
					}
					b.append(c);
				}
				return b.toString();
			}
		},
		/**
		 * Plain Windows command-line arguments for the C runtime
		 * 
		 * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw">CommandLineToArgvWfunction</a>
		 */
		WINDOWS {
			/**
			 * Derived from <a href=
			 * "https://learn.microsoft.com/en-us/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way">Everyone
			 * quotes command line arguments the wrong way</a>
			 * <p>
			 * The section titled "The Correct Solution" invites its readers to "translate it into
			 * your language and coding style off choice."
			 */
			@Override
			public String generateArgument(String a) {
				if (!a.isEmpty() && a.indexOf(' ') == -1 && a.indexOf('\t') == -1 &&
					a.indexOf('\n') == -1 && a.indexOf('"') == -1) {
					return a;
				}
				StringBuilder b = new StringBuilder();
				b.append('"');
				for (int i = 0;; i++) {
					int nBackSlash = 0;
					while (i < a.length() && a.charAt(i) == '\\') {
						i++;
						nBackSlash++;
					}

					if (i == a.length()) {
						/**
						 * We reached the end of the argument while counting backslashes. Escape
						 * them all. The terminating " we add at the end of this method will be
						 * interpreted as a metacharacter.
						 */
						b.append("\\".repeat(nBackSlash * 2));
						break;
					}
					else if (a.charAt(i) == '"') {
						/**
						 * Sequence of backslashes ends in a ". Escape them all, including the ".
						 */
						b.append("\\".repeat(nBackSlash * 2 + 1));
						b.append(a.charAt(i));
					}
					else {
						/**
						 * They're just literal backslashes. Do not escape them. Be sure to add the
						 * current character, too.
						 */
						b.append("\\".repeat(nBackSlash)); // No *2
						b.append(a.charAt(i));
					}
				}
				b.append('"');
				return b.toString();
			}
		},
		/**
		 * The Windows cmd.exe shell.
		 * <p>
		 * <b>NOTE:</b> It seems to me using this with {@link ShellUtils#generateLine(List, Shell)}
		 * is futile, if the intent is to use specific argument numbers in the batch file, e.g.,
		 * <code>%1</code>. If you make clear certain constraints to the user, maybe it's suitable,
		 * but especially involving quotes, it's not possible to encode any arbitrary string. It
		 * seems the cmd shell is primarily concerned with just passing the arguments along to child
		 * processes, as encoded, and then the child figures out the parsing. That said, if the
		 * child process parses to argc/argv, then so long as the <em>full</em> command line is
		 * passed through the batch file, it should work as intended. However, if grabbing
		 * individual arguments, they cannot be reliably controlled.
		 * <p>
		 * LATER: There may be a way to factor the escaping part separately from the argument
		 * catenation part, so that special logic can be applied here to better guarantee argument
		 * numbering, but then there's still the issue if the final target is expected to parse to
		 * argc/argv, if that can be encoded reliably.
		 */
		WINDOWS_CMD {
			@Override
			public String generateArgument(String a) {
				String quoted = WINDOWS.generateArgument(a);
				StringBuilder b = new StringBuilder();
				for (int i = 0; i < quoted.length(); i++) {
					char c = quoted.charAt(i);
					/**
					 * The list and rationale for each metacharacter comes from the same blogpost:
					 * <a href=
					 * "https://learn.microsoft.com/en-us/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way">Everyone
					 * quotes command line arguments the wrong way</a>
					 */
					boolean esc = switch (c) {
						case '(', ')', '%', '!', '<', '>', '&', '|', // Metacharacters
								'"', // Prevent cmd from interpreting quotes
								'^' // The escape character itself
								-> true;
						default -> false;
					};
					if (esc) {
						b.append('^');
					}
					b.append(c);
				}
				return b.toString();
			}
		};

		/**
		 * Get the probable shell for the given operating system
		 * 
		 * @param os the operating system
		 * @return the shell, probably
		 */
		public static Shell forOs(OperatingSystem os) {
			return switch (os) {
				case OperatingSystem.WINDOWS -> Shell.WINDOWS;
				default -> Shell.UNIX_SH;
			};
		}

		/**
		 * The local shell, probably
		 */
		public static final Shell LOCAL = forOs(Platform.CURRENT_PLATFORM.getOperatingSystem());

		/**
		 * Escape and/or quote a single command-line argument
		 * 
		 * @param a the argument
		 * @return the argument formed in such a way that the shell will interpret it as the given
		 *         string in one argument
		 */
		public abstract String generateArgument(String a);
	}

	public static String generateEnvBlock(Map<String, String> env) {
		return env.entrySet()
				.stream()
				.map(e -> e.getKey() + "=" + e.getValue() + "\0")
				.collect(Collectors.joining()); // NB. JNA adds final terminator
	}
}
