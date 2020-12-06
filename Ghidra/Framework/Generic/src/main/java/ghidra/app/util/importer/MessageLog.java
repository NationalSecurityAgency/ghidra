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
package ghidra.app.util.importer;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A simple class to handle logging messages and exceptions.  A maximum message count size 
 * constraint can be set to clip messages after a certain number, but still keep incrementing
 * a running total.
 * 
 * <p>In addition to logging messages, clients can also set a status message.  This message may
 * later used as the primary error message when reporting to the user.
 */
public class MessageLog {
	/**
	 * The default number of messages to store before clipping
	 */
	private final static int MAX_COUNT = 500;

	private List<String> messages = new ArrayList<>();
	private int maxSize = MAX_COUNT;
	private int count;
	private String statusMsg = StringUtils.EMPTY;

	/**
	 * Copies the contents of one message log into this one
	 * @param log the log to copy from
	 */
	public void copyFrom(MessageLog log) {
		for (String otherMessage : log.messages) {
			add(otherMessage);
		}
	}

	/**
	 * Appends the message to the log
	 * @param message the message
	 */
	public void appendMsg(String message) {
		add(message);
	}

	/**
	 * Appends the message to the log
	 *
	 * @param originator the originator of the message 
	 * @param message the message
	 */
	public void appendMsg(String originator, String message) {
		if (originator == null) {
			add(message);
		}
		else {
			add(originator + "> " + message);
		}
	}

	/**
	 * Appends the message and line number to the log
	 * @param lineNum the line number that generated the message
	 * @param message the message
	 */
	public void appendMsg(int lineNum, String message) {
		add("Line #" + lineNum + " - " + message);
	}

	/**
	 * Appends the exception to the log
	 * @param t the exception to append to the log
	 */
	public void appendException(Throwable t) {
		String asString = ReflectionUtilities.stackTraceToString(t);
		add(asString);
	}

	/**
	 * Readable method for appending error messages to the log.
	 *
	 * <p>Currently does nothing different than {@link #appendMsg(String, String)}.
	 *
	 *
	 * @param originator the originator of the message 
	 * @param message the message
	 * @deprecated use {@link #appendMsg(String)}
	 */
	@Deprecated
	public void error(String originator, String message) {
		appendMsg(originator, message);
	}

	/**
	 * Returns true if this log has messages
	 * @return true if this log has messages
	 */
	public boolean hasMessages() {
		return count > 0;
	}

	/**
	 * Clears all messages from this log and resets the count
	 */
	public void clear() {
		messages = new ArrayList<>();
		count = 0;
	}

	/**
	 * Stores a status message that can be used elsewhere (i.e., populate warning dialogs)
	 * @param status the status message
	 */
	public void setStatus(String status) {
		statusMsg = status;
	}

	/**
	 * Clear status message
	 */
	public void clearStatus() {
		statusMsg = StringUtils.EMPTY;
	}

	/**
	 * Returns a stored status message
	 * @return stored status message
	 */
	public String getStatus() {
		return statusMsg;
	}

	@Override
	public String toString() {
		return toStringWithWarning();
	}

	/**
	 * Writes this log's contents to the application log
	 * @param owner the owning class whose name will appear in the log message
	 * @param messageHeader the message header that will appear before the log messages
	 */
	public void write(Class<?> owner, String messageHeader) {
		String header = StringUtils.defaultIfBlank(messageHeader, "Log Messages");
		Msg.info(owner, header + '\n' + toStringWithWarning());
	}

	private String toStringWithWarning() {
		StringBuilder output = new StringBuilder();
		if (count > maxSize) {
			output.append("There were too many messages to display.\n");
			output.append((count - maxSize)).append(" messages have been truncated.\n");
			output.append('\n');
		}

		for (String s : messages) {
			output.append(s).append('\n');
		}
		return output.toString();
	}

	private void add(String msg) {
		if (StringUtils.isBlank(msg)) {
			return;
		}

		if (count++ < maxSize) {
			messages.add(msg);
		}
	}
}
