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
package log;

/**
 * An interface that allows clients to receive log messages.
 */
public interface LogListener {

	/**
	 * Called when a log message is received.
	 * 
	 * @param message the message of the log event
	 * @param isError true if the message is considered an error, as opposed to an informational
	 *        message.
	 */
	public void messageLogged(String message, boolean isError);
}
