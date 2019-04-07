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

import java.io.PrintStream;

public class DefaultErrorLogger implements ErrorLogger {

	private void output(PrintStream stream, Object message) {
		stream.println(message);
	}

	private void out(Object message) {
		output(System.out, message);
	}

	private void err(Object message) {
		output(System.err, message);
	}

	@Override
	public void debug(Object originator, Object message) {
		out(message);
	}

	@Override
	public void debug(Object originator, Object message, Throwable throwable) {
		if (throwable != null) {
			err(message);
			String throwableMessage = throwable.getMessage();
			if (throwableMessage != null) {
				err(throwableMessage);
			}
			throwable.printStackTrace(System.err);
		}
		else {
			out(message);
		}
	}

	@Override
	public void error(Object originator, Object message) {
		err(message);
	}

	@Override
	public void error(Object originator, Object message, Throwable throwable) {
		err(message);
		if (throwable != null) {
			throwable.printStackTrace(System.err);
		}
	}

	@Override
	public void info(Object originator, Object message) {
		out(message);
	}

	@Override
	public void info(Object originator, Object message, Throwable throwable) {
		if (throwable != null) {
			err(message);
			String throwableMessage = throwable.getMessage();
			if (throwableMessage != null) {
				err(throwableMessage);
			}
			throwable.printStackTrace(System.err);
		}
		else {
			out(message);
		}
	}

	@Override
	public void trace(Object originator, Object message) {
		// guess we don't support tracing?
	}

	@Override
	public void trace(Object originator, Object message, Throwable throwable) {
		// guess we don't support tracing?
	}

	@Override
	public void warn(Object originator, Object message) {
		err(message);
	}

	@Override
	public void warn(Object originator, Object message, Throwable throwable) {
		err(message);
		if (throwable != null) {
			throwable.printStackTrace(System.err);
		}
	}
}
