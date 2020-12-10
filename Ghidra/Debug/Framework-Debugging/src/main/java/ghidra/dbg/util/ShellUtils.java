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
package ghidra.dbg.util;

import java.util.ArrayList;
import java.util.List;

public class ShellUtils {
	enum State {
		NORMAL, NORMAL_ESCAPE, DQUOTE, DQUOTE_ESCAPE, SQUOTE, SQUOTE_ESCAPE;
	}

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

	public static String generateLine(List<String> args) {
		if (args.isEmpty()) {
			return "";
		}
		StringBuilder line = new StringBuilder(args.get(0));
		for (int i = 1; i < args.size(); i++) {
			String a = args.get(i);
			if (a.contains(" ")) {
				if (a.contains("\"")) {
					if (a.contains("'")) {
						line.append(" \"");
						line.append(a.replace("\"", "\\\""));
						line.append("\"");
						continue;
					}
					line.append(" '");
					line.append(a);
					line.append("'");
					continue;
				}
				line.append(" \"");
				line.append(a);
				line.append("\"");
				continue;
			}
			line.append(" ");
			line.append(a);
		}
		return line.toString();
	}
}
