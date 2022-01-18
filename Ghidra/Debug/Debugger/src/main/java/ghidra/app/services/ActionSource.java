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
package ghidra.app.services;

/**
 * Possible sources that drive actions or method invocations
 * 
 * <p>
 * This is primarily used to determine where and how errors should be reported. Granted, this is
 * only one factor in determining how to deliver an error message. In general, actions which are
 * taken automatically should not cause disruptive error messages.
 */
public enum ActionSource {
	/**
	 * The action was requested by the user, usually via a UI action. It is acceptable to display an
	 * error message.
	 */
	MANUAL,
	/**
	 * The action was requested automatically, usually by some background thread. Error messages
	 * should probably be delivered to the log or Debug Console, since displaying an error pop-up
	 * would seem to "come from nowhere."
	 */
	AUTOMATIC;
}
