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
package ghidra.features.bsim.query;

import ghidra.util.DefaultErrorLogger;

public class MinimalErrorLogger extends DefaultErrorLogger {
	@Override
	public void debug(Object originator, Object message) {
		// Squash DEBUG messages
	}

	@Override
	public void debug(Object originator, Object message, Throwable throwable) {
		// Squash DEBUG messages
	}

	@Override
	public void info(Object originator, Object message) {
		// Squash INFO messages
	}

	@Override
	public void info(Object originator, Object message, Throwable throwable) {
		// Squash INFO messages
	}

	@Override
	public void error(Object originator, Object message) {
		System.err.println(message);
	}

	@Override
	public void error(Object originator, Object message, Throwable throwable) {
		System.err.println(message);
		// Don't print stack trace
	}

	@Override
	public void warn(Object originator, Object message) {
		// Squash WARN messages
	}

	@Override
	public void warn(Object originator, Object message, Throwable throwable) {
		// Squash WARN messages
	}
}
