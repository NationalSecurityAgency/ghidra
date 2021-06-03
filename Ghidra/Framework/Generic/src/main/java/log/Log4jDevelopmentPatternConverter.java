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

import java.io.PrintWriter;
import java.io.StringWriter;

import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.pattern.ConverterKeys;
import org.apache.logging.log4j.core.pattern.LogEventPatternConverter;

import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

/**
 * Pattern converter for Log4j 2.x that adds a hyperlink for the calling class
 * of the current log message. This is to be used in log4j configurations as part
 * of a pattern layout. eg:
 * 
 * 		{@literal <PatternLayout pattern="%-5p %m %hl %n"/>} 
 * 
 * See generic.log4jdev.xml for a working example.
 */
@Plugin(name = "DevPatternConverter", category = "Converter")
@ConverterKeys({ "hl", "hyperlinker" })
public class Log4jDevelopmentPatternConverter extends LogEventPatternConverter {

	// this allows us to take advantage of refactoring
	private static final String TOOL_MESSAGE_SERVICE_CLASSNAME = Msg.class.getName();
	private static final String TOOL_MESSAGE_SERVICE_FILENAME = Msg.class.getSimpleName() + ".java";
	private static final String LOGGER_PACKAGE = ".logging.";
	private static final String PRINT_STACK_TRACE_METHOD_NAME = "printStackTrace";

	//@formatter:off
	private static final MethodPattern[] KNOWN_IGNORE_METHODS = {
		// logging system
		new MethodPattern("trace"), 
		new MethodPattern("debug"),
		new MethodPattern("info"), 
		new MethodPattern("warn"),
		new MethodPattern("error"),
		
		// some API log utility methods names
		new MethodPattern("log"),
		
		// scripting
		new MethodPattern("println"), 
		new MethodPattern("printerr"), 
		new MethodPattern("printf")
		};
	//@formatter:on

	private static final String EMPTY_STRING = "";

	private StringWriter stringWriter = new StringWriter();
	private PrintWriter printWriter = new PrintWriter(stringWriter);
	private StringBuilder buffer = new StringBuilder(100);

	/**
	 * Required constructor.
	 * 
	 * @param name the name of the converter
	 * @param style the style of the converter
	 */
	protected Log4jDevelopmentPatternConverter(String name, String style) {
		super(name, style);
	}

	/**
	 * Required instance method for all log4j 2.x converters.
	 * 
	 * @param options unused
	 * @return new converter instance
	 */
	public static Log4jDevelopmentPatternConverter newInstance(String[] options) {
		return new Log4jDevelopmentPatternConverter("hyperlinker", "hyperlinker");
	}

	/**
	 * Appends the desired hyperlink to the existing event message.
	 * 
	 * @param event the current log event
	 * @param toAppendTo the string to append to
	 */
	@Override
	public void format(LogEvent event, StringBuilder toAppendTo) {
		String callerInformation = getCallerInformation();
		toAppendTo.append(callerInformation);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private String getCallerInformation() {
		Throwable throwable = new Throwable();

		// First, for a quick filter, ignore any logging API packaging
		StackTraceElement[] trace = throwable.getStackTrace();
		trace = ReflectionUtilities.movePastStackTracePattern(trace, LOGGER_PACKAGE);
		throwable.setStackTrace(trace);

		// Get the full string for easy string checking; must be synchronized, since the logger
		// is used by multiple threads
		String stackString = null;
		synchronized (stringWriter) {
			throwable.printStackTrace(printWriter);
			stackString = stringWriter.toString();
			stringWriter.getBuffer().setLength(0); // reset
		}

		//
		// Don't print out locations for stack traces, as they already have that info		
		//
		if (stackString.indexOf(PRINT_STACK_TRACE_METHOD_NAME) >= 0) {
			return EMPTY_STRING;
		}

		// 
		// Alter how we find our desired source (depending upon whether we have a messaging service)
		// 
		String cutoffName = getHighestLevelMethodNameToIgnore(stackString);
		return getLogMessageCallerInformation(trace, cutoffName);
	}

	private String getHighestLevelMethodNameToIgnore(String stackString) {

		String cutoffName = EMPTY_STRING;
		int bestIndex = -1;

		// 1) see if we are using a system messaging service
		int index = stackString.indexOf(TOOL_MESSAGE_SERVICE_CLASSNAME);
		if (index >= 0) {
			// assumption: this call to the Messaging 
			bestIndex = index;
			cutoffName = TOOL_MESSAGE_SERVICE_CLASSNAME;
		}

		// 2) ignore any homegrown printing methods (like those found in scripting)
		for (MethodPattern excludePattern : KNOWN_IGNORE_METHODS) {
			String pattern = excludePattern.getMethodPattern();
			index = stackString.indexOf(pattern);
			if (index < 0 || index < bestIndex) {
				continue;
			}

			bestIndex = index;
			cutoffName = excludePattern.getMethodName();
		}

		return cutoffName;
	}

	private String getLogMessageCallerInformation(StackTraceElement[] trace, String cutoffName) {

		int lastIndexOfCutoffFilename = -1;
		for (int i = 0; i < trace.length; i++) {
			StackTraceElement element = trace[i];
			String className = element.getClassName();
			String methodName = element.getMethodName();

			// assumption: we have to walk the list of elements until we get past all calls to 
			// the logging API (and maybe a Ghidra API call)
			if (cutoffName.equals(className) || cutoffName.equals(methodName)) {
				lastIndexOfCutoffFilename = i;
			}
		}

		// we want the first filename after the cutoff; we may not have a cutoff
		lastIndexOfCutoffFilename++;

		if (lastIndexOfCutoffFilename >= trace.length) {
			return EMPTY_STRING; // shouldn't happen
		}
		return buildFileInfo(trace[lastIndexOfCutoffFilename]);
	}

	private String buildFileInfo(StackTraceElement stackTraceElement) {
		String filename = stackTraceElement.getFileName();
		int lineNumber = stackTraceElement.getLineNumber();

		synchronized (buffer) { // lock the shared resource   
			buffer.append(' ').append('(');
			buffer.append(filename);
			buffer.append(':');
			buffer.append(lineNumber);
			buffer.append(')');
			String value = buffer.toString();
			buffer.delete(0, buffer.length());
			return value;
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	// Note: this class is multithreaded, so be sure to be immutable
	private static class MethodPattern {

		private final String methodName;
		private final String methodPattern;

		MethodPattern(String methodName) {
			this.methodName = methodName;
			this.methodPattern = "." + methodName + "(";
		}

		String getMethodPattern() {
			return methodPattern;
		}

		String getMethodName() {
			return methodName;
		}

		@Override
		public String toString() {
			return methodPattern;
		}
	}
}
