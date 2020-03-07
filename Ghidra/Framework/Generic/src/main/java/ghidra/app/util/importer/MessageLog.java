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

import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * A simple class to handle logging messages and exceptions.  A maximum message count size 
 * constraint can be set to clip messages after a certain number, but still keep incrementing
 * a running total.
 */
public class MessageLog {
	/**
	 * The default number of messages to store before clipping
	 */
	public final static int MAX_COUNT = 500;

	private StringBuffer buffer = new StringBuffer();
	private int maxSize;
	private int count;
	private int pos = -1;
	private String statusMsg;

	/**
	 * Constructs a new message log using the default message count
	 */
	public MessageLog() {
		this(MAX_COUNT);
	}

	/**
	 * Constructs a new message log using the specified message count
	 * @param maxSize the maximum number of messages
	 */
	public MessageLog(int maxSize) {
		this.maxSize = maxSize;
		clearStatus();
	}

	/**
	 * Copies the contents of one message log into this one
	 * @param log the log to copy from
	 */
	public void copyFrom(MessageLog log) {
		this.buffer = new StringBuffer(log.buffer);
		this.maxSize = log.maxSize;
		this.count = log.count;
		this.pos = log.pos;
	}

	/**
	 * Appends the message to the log
	 * @param message the message
	 */
	public void appendMsg(String message) {
		msg(message);
	}

	/**
	 * Appends the message to the log
	 *
	 * @param originator the originator of the message 
	 * @param message the message
	 */
	public void appendMsg(String originator, String message) {
		if (originator == null) {
			msg(message);
		}
		else {
			msg(originator + "> " + message);
		}
	}

	/**
	 * Appends the message and line number to the log
	 * @param lineNum the line number that generated the message
	 * @param message the message
	 */
	public void appendMsg(int lineNum, String message) {
		msg("Line #" + lineNum + " - " + message);
	}

	/**
	 * Appends the exception to the log
	 * @param t the exception to append to the log
	 */
	public void appendException(Throwable t) {
		if (t instanceof NullPointerException || t instanceof AssertException) {
			Msg.error(this, "Exception appended to MessageLog", t);
		}
		else {
			Msg.debug(this, "Exception appended to MessageLog", t);
		}
		String msg = t.toString();
		msg(msg);
	}

	/**
	 * Returns the message count
	 * @return the message count
	 */
	public int getMsgCount() {
		return count;
	}

	/**
	 * Clears all messages from this log and resets the count
	 */
	public void clear() {
		buffer = new StringBuffer();
		count = 0;
		pos = -1;
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
		statusMsg = "";
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
		if (count > maxSize) {
			if (pos > -1) {
				buffer.delete(pos, buffer.length());
			}
			pos = buffer.length();
			buffer.append("\n \n");
			buffer.append("There were too many messages to display.\n");
			buffer.append("" + (count - maxSize) + " messages have been truncated.");
			buffer.append("\n \n");
		}
		return buffer.toString();
	}

	private void msg(String msg) {
		if (msg == null || msg.length() == 0) {//discard if null...
			return;
		}
		if (count++ < maxSize) {
			buffer.append(msg);
			buffer.append("\n");
		}
	}

	/**
	 * Readable method for appending error messages to the log.
	 *
	 * <p>Currently does nothing different than {@link #appendMsg(String, String)}.
	 *
	 *
	 * @param originator the originator of the message 
	 * @param message the message
	 */
	public void error(String originator, String message) {
		appendMsg(originator, message);
	}
}
