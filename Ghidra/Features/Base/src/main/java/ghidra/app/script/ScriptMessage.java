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
package ghidra.app.script;

import org.apache.logging.log4j.message.Message;

/**
 * A simple {@link Message} implementation that allows us to use the filtering capability 
 * of log4j.  This class has a formatted and unformatted message.  log4j writes the the formatted
 * message out.  Our formatted message is the original message given to us.   We use the 
 * unformatted message, in conjunction with a regex filter to allow for filtering such that 
 * the script log file only has script messages.
 * 
 * <P>See logj4-appender-rolling-file-scripts.xml
 */
public class ScriptMessage implements Message {

	private String message;

	public ScriptMessage(String message) {
		this.message = message;
	}

	@Override
	public String getFormattedMessage() {
		// the "formatted" message that will be emitted; this is the original client messages
		return message;
	}

	@Override
	public String getFormat() {
		// special message used by filter when 'useRawMsg="true"'; this is the "raw" message used
		// by log4j when running its filter
		return "Format:GhidraScript" + getFormattedMessage();
	}

	@Override
	public Object[] getParameters() {
		return null;
	}

	@Override
	public Throwable getThrowable() {
		return null;
	}
}
