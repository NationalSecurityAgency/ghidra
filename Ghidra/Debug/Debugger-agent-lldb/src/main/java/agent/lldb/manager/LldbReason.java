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
package agent.lldb.manager;

public interface LldbReason {

	/**
	 * Reasons other than those given by LLDB
	 */
	enum Reasons implements LldbReason {
		/**
		 * No reason was given
		 */
		NONE,
		/**
		 * A reason was given, but the manager does not understand it
		 */
		UNKNOWN;

		@Override
		public String desc() {
			return "Unknown";
		}
	}

	static LldbReason getReason(String info) {
		return Reasons.UNKNOWN;
	}

	public String desc();
}
