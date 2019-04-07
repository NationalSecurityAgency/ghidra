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
package ghidra.app.util.headless;

import java.io.*;

import ghidra.util.ErrorLogger;

/**
 * Custom headless error logger which is used when log4j is disabled.
 */
class HeadlessErrorLogger implements ErrorLogger {

	private PrintWriter logWriter;

	HeadlessErrorLogger(File logFile) {
		if (logFile != null) {
			setLogFile(logFile);
		}
	}

	synchronized void setLogFile(File logFile) {
		try {
			if (logFile == null) {
				if (logWriter != null) {
					writeLog("INFO", "File logging disabled");
					logWriter.close();
					logWriter = null;
				}
				return;
			}
			PrintWriter w = new PrintWriter(new FileWriter(logFile));
			if (logWriter != null) {
				writeLog("INFO ", "Switching log file to: " + logFile);
				logWriter.close();
			}
			logWriter = w;
		}
		catch (IOException e) {
			System.err.println("Failed to open log file " + logFile + ": " + e.getMessage());
		}
	}

	private synchronized void writeLog(String line) {
		if (logWriter == null) {
			return;
		}
		logWriter.println(line);
	}

	private synchronized void writeLog(String level, String[] lines) {
		if (logWriter == null) {
			return;
		}
		for (String line : lines) {
			writeLog(level + " " + line);
		}
		logWriter.flush();
	}

	private synchronized void writeLog(String level, String text) {
		if (logWriter == null) {
			return;
		}
		writeLog(level, chopLines(text));
	}

	private synchronized void writeLog(String level, String text, Throwable throwable) {
		if (logWriter == null) {
			return;
		}
		writeLog(level, chopLines(text));
		for (StackTraceElement element : throwable.getStackTrace()) {
			writeLog(level + " " + element.toString());
		}
		logWriter.flush();
	}

	private String[] chopLines(String text) {
		text = text.replace("\r", "");
		return text.split("\n");
	}

	@Override
	public void debug(Object originator, Object message) {
		// TODO for some reason debug is off
		// writeLog("DEBUG", message.toString());
	}

	@Override
	public void debug(Object originator, Object message, Throwable throwable) {
		// TODO for some reason debug is off
		// writeLog("DEBUG", message.toString(), throwable);
	}

	@Override
	public void error(Object originator, Object message) {
		writeLog("ERROR", message.toString());
	}

	@Override
	public void error(Object originator, Object message, Throwable throwable) {
		writeLog("ERROR", message.toString(), throwable);
	}

	@Override
	public void info(Object originator, Object message) {
		writeLog("INFO ", message.toString());
	}

	@Override
	public void info(Object originator, Object message, Throwable throwable) {
		// TODO for some reason tracing is off
		// writeLog("INFO ", message.toString(), throwable);
	}

	@Override
	public void trace(Object originator, Object message) {
		// TODO for some reason tracing i soff
		// writeLog("TRACE", message.toString());
	}

	@Override
	public void trace(Object originator, Object message, Throwable throwable) {
		// TODO for some reason tracing is off
		// writeLog("TRACE", message.toString(), throwable);
	}

	@Override
	public void warn(Object originator, Object message) {
		writeLog("WARN ", message.toString());
	}

	@Override
	public void warn(Object originator, Object message, Throwable throwable) {
		writeLog("WARN ", message.toString(), throwable);
	}

}
