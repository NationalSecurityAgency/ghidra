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
package ghidra.util;

import java.awt.Component;

public class ConsoleErrorDisplay implements ErrorDisplay {

	private void displayMessage(MessageType messageType, ErrorLogger logger, Object originator,
			final Component parent, final String title, final Object message,
			final Throwable throwable) {

		if (title == null || message == null) {
			RuntimeException re = new RuntimeException(
				"Please clean up Err log statement with null title or message; " +
					"about the sixth line down from here");
			System.err.println(
				"Found a null title or message; please find the source and add detail:");
			re.printStackTrace(System.err);
		}

		if (throwable != null) {
			switch (messageType) {
				case INFO:
					logger.info(originator, title + ": " + message);
					break;
				case WARNING:
				case ALERT:
					logger.warn(originator, title + ": " + message, throwable);
					break;
				case ERROR:
					logger.error(originator, title + ": " + message, throwable);
					break;
			}
		}
		else {
			switch (messageType) {
				case INFO:
					logger.info(originator, title + ": " + message);
					break;
				case WARNING:
				case ALERT:
					logger.warn(originator, title + ": " + message);
					break;
				case ERROR:
					logger.error(originator, title + ": " + message);
					break;
			}
		}
	}

	@Override
	public void displayInfoMessage(ErrorLogger logger, Object originator, Component parent,
			String title, Object message) {
		displayMessage(MessageType.INFO, logger, originator, parent, title, message, null);
	}

	@Override
	public void displayErrorMessage(ErrorLogger logger, Object originator, Component parent,
			String title, Object message, Throwable throwable) {
		displayMessage(MessageType.ERROR, logger, originator, parent, title, message, throwable);
	}

	@Override
	public void displayWarningMessage(ErrorLogger logger, Object originator, Component parent,
			String title, Object message, Throwable throwable) {
		displayMessage(MessageType.WARNING, logger, originator, parent, title, message, throwable);
	}
}
