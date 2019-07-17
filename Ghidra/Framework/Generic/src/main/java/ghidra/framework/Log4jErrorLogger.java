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
package ghidra.framework;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.Message;

import ghidra.util.ErrorLogger;

public class Log4jErrorLogger implements ErrorLogger {

	private static Logger getLogger(Object originator) {
		if (originator == null) {
			return LogManager.getLogger("(null)");
		}
		else if (originator instanceof Logger) {
			return (Logger) originator;
		}
		else if (originator instanceof Class<?>) {
			return LogManager.getLogger((Class<?>) originator);
		}
		else if (originator instanceof String) {
			return LogManager.getLogger((String) originator);
		}
		else {
			return LogManager.getLogger(originator.getClass());
		}
	}

	@Override
	public void debug(Object originator, Object message) {

		if (message instanceof Message) {
			getLogger(originator).debug((Message) message);
		}
		else {
			getLogger(originator).debug(message);
		}
	}

	@Override
	public void debug(Object originator, Object message, Throwable throwable) {

		if (message instanceof Message) {
			getLogger(originator).debug((Message) message, throwable);
		}
		else {
			getLogger(originator).debug(message, throwable);
		}
	}

	@Override
	public void error(Object originator, Object message) {

		if (message instanceof Message) {
			getLogger(originator).error((Message) message);
		}
		else {
			getLogger(originator).error(message);
		}
	}

	@Override
	public void error(Object originator, Object message, Throwable throwable) {

		if (message instanceof Message) {
			getLogger(originator).error((Message) message, throwable);
		}
		else {
			getLogger(originator).error(message, throwable);
		}
	}

	@Override
	public void info(Object originator, Object message) {

		if (message instanceof Message) {
			getLogger(originator).info((Message) message);
		}
		else {
			getLogger(originator).info(message);
		}
	}

	@Override
	public void info(Object originator, Object message, Throwable throwable) {

		if (message instanceof Message) {
			getLogger(originator).info((Message) message, throwable);
		}
		else {
			getLogger(originator).info(message, throwable);
		}
	}

	@Override
	public void trace(Object originator, Object message) {

		if (message instanceof Message) {
			getLogger(originator).trace((Message) message);
		}
		else {
			getLogger(originator).trace(message);
		}
	}

	@Override
	public void trace(Object originator, Object message, Throwable throwable) {

		if (message instanceof Message) {
			getLogger(originator).trace((Message) message, throwable);
		}
		else {
			getLogger(originator).trace(message, throwable);
		}
	}

	@Override
	public void warn(Object originator, Object message) {

		if (message instanceof Message) {
			getLogger(originator).warn((Message) message);
		}
		else {
			getLogger(originator).warn(message);
		}
	}

	@Override
	public void warn(Object originator, Object message, Throwable throwable) {

		if (message instanceof Message) {
			getLogger(originator).warn((Message) message, throwable);
		}
		else {
			getLogger(originator).warn(message, throwable);
		}
	}
}
