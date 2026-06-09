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
package ghidra.dbg.jdi.manager;

public interface JdiConsoleOutputListener {
	/**
	 * For console output notifications, indicates whether it is normal or error output
	 */
	public static enum Channel {
		STDOUT, STDERR;
	}

	/**
	 * JDI outputted some text
	 * 
	 * <p>
	 * TODO: Do not depend on TargetObject API at the manager level. Make two callbacks, or define
	 * our own Channel enum.
	 * 
	 * @param channel indicates stderr or stdout
	 * @param out the output
	 */
	void output(Channel channel, String out);
}
