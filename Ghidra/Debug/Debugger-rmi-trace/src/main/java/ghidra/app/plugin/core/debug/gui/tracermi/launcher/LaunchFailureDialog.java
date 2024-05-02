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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import java.util.Map.Entry;

import docking.widgets.OptionDialog;
import ghidra.debug.api.tracermi.TerminalSession;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult;
import ghidra.util.HTMLUtilities;

public class LaunchFailureDialog extends OptionDialog {
	private static final String MSGPAT_PART_TOP = """
			<html><body width="400px">
			<h3>Failed to launch %s due to an exception:</h3>

			<tt>%s</tt>

			<h3>Troubleshooting</h3>
			<p>
			<b>Check the Terminal!</b>
			If no terminal is visible, check the menus: <b>Window &rarr; Terminals &rarr;
			...</b>.
			A path or other configuration parameter may be incorrect.
			The back-end debugger may have paused for user input.
			There may be a missing dependency.
			There may be an incorrect version, etc.</p>

			""";
	private static final String MSGPAT_PART_RESOURCES = """
			<h3>These resources remain after the failed launch:</h3>
			<ul>
			%s
			</ul>

			<h3>How do you want to proceed?</h3>
			<ul>
			<li>Choose <b>Keep</b> to stop here and diagnose or complete the launch manually.</li>
			<li>Choose <b>Retry</b> to clean up and retry at the launch dialog.</li>
			<li>Choose <b>Cancel</b> to clean up without retrying.</li>
			</ul>
			""";
	private static final String MSGPAT_WITH_RESOURCES = MSGPAT_PART_TOP + MSGPAT_PART_RESOURCES;
	private static final String MSGPAT_WITHOUT_RESOURCES = MSGPAT_PART_TOP;

	public enum ErrPromptResponse {
		KEEP, RETRY, TERMINATE;
	}

	protected static String formatMessage(LaunchResult result) {
		return hasResources(result)
				? MSGPAT_WITH_RESOURCES.formatted(htmlProgramName(result),
					htmlExceptionMessage(result), htmlResources(result))
				: MSGPAT_WITHOUT_RESOURCES.formatted(htmlProgramName(result),
					htmlExceptionMessage(result));
	}

	protected static String htmlProgramName(LaunchResult result) {
		if (result.program() == null) {
			return "";
		}
		return "<tt>" + HTMLUtilities.escapeHTML(result.program().getName()) + "</tt>";
	}

	protected static String htmlExceptionMessage(LaunchResult result) {
		if (result.exception() == null) {
			return "(No exception)";
		}
		return HTMLUtilities.escapeHTML(result.exception().toString());
	}

	protected static boolean hasResources(LaunchResult result) {
		return !result.sessions().isEmpty() ||
			result.acceptor() != null ||
			result.connection() != null ||
			result.trace() != null;
	}

	protected static String htmlResources(LaunchResult result) {
		StringBuilder sb = new StringBuilder();
		for (Entry<String, TerminalSession> ent : result.sessions().entrySet()) {
			TerminalSession session = ent.getValue();
			sb.append("<li>Terminal: %s &rarr; <tt>%s</tt>".formatted(
				HTMLUtilities.escapeHTML(ent.getKey()),
				HTMLUtilities.escapeHTML(session.description())));
			if (session.isTerminated()) {
				sb.append(" (Terminated)");
			}
			sb.append("</li>\n");
		}
		if (result.acceptor() != null) {
			sb.append("<li>Acceptor: <tt>%s</tt></li>\n".formatted(
				HTMLUtilities.escapeHTML(result.acceptor().getAddress().toString())));
		}
		if (result.connection() != null) {
			sb.append("<li>Connection: <tt>%s</tt></li>\n".formatted(
				HTMLUtilities.escapeHTML(result.connection().getRemoteAddress().toString())));
		}
		if (result.trace() != null) {
			sb.append("<li>Trace: %s</li>\n".formatted(
				HTMLUtilities.escapeHTML(result.trace().getName())));
		}
		return sb.toString();
	}

	public static ErrPromptResponse show(LaunchResult result) {
		return switch (new LaunchFailureDialog(result).show()) {
			case OptionDialog.YES_OPTION -> ErrPromptResponse.KEEP;
			case OptionDialog.NO_OPTION -> ErrPromptResponse.RETRY;
			case OptionDialog.CANCEL_OPTION -> ErrPromptResponse.TERMINATE;
			default -> throw new AssertionError();
		};
	}

	protected LaunchFailureDialog(LaunchResult result) {
		super("Launch Failed", formatMessage(result), hasResources(result) ? "&Keep" : null,
			"&Retry", OptionDialog.ERROR_MESSAGE, null, true, "Retry");
	}
}
