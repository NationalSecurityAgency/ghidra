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

/**
 * <code>StatusListener</code> is a general purpose status listener
 * responsible for displaying and/or recording status messages
 */
public interface StatusListener {

	/**
	 * Set the current status as type INFO
	 * @param text status text
	 */
	void setStatusText(String text);

	/**
	 * Set the current status as the specified type
	 * @param text status text
	 * @param type status type
	 */
	void setStatusText(String text, MessageType type);

	/**
	 * Set the current status as the specified type
	 * @param text status text
	 * @param type status type
	 * @param alert true to grab the user's attention
	 */
	void setStatusText(String text, MessageType type, boolean alert);

	/**
	 * Clear the current status - same as setStatusText("")
	 * without being recorded
	 */
	void clearStatusText();
}
