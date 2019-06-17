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
package ghidra.pdb;

import java.io.*;
import java.util.function.Supplier;

import generic.io.NullWriter;
import ghidra.framework.Application;

/**
 * A utility class providing logging for: PDB parsing and PDB analysis.  It includes data and
 * metrics for the purposes of debugging and aiding in continued research and development of
 * this package.
 */
public class PdbLog {

	private static File logFile;
	private static Writer nullWriter = new NullWriter();
	private static Writer fileWriter;
	private static Writer writer = nullWriter;
	private static boolean enabled;

	/**
	 * Enable or disable future messages to be output to the appropriate log resource.  This
	 * method gives control to the client to be able to turn on/off the messaging output without
	 * having to do conditional checks at each point that one of the messaging methods is called.
	 * @param enable {@code true} to enable logging; {@code false} to disable logging.  Initial
	 * state is {@code false}.
	 * @throws IOException upon problem creating a {@link FileWriter}.
	 * @see #message(String)
	 * @see #message(String, Supplier...)
	 */
	public static void setEnabled(boolean enable) throws IOException {
		if (fileWriter == null) {
			fileWriter = createFileWriter();
		}
		if (nullWriter == null) {
			// Doing this here, even though statically assigned above, just in case dispose() was
			// called prematurely.
			nullWriter = new NullWriter();
		}
		writer = enable ? fileWriter : nullWriter;
		enabled = enable;
	}

	/**
	 * Outputs a message to the PDB log if messaging has been enable, else ignored.  This method
	 * uses a format string and a variable arguments list of lambdas to allow for deferred
	 * processing of the message to output.  Thus, when message output is disabled, the client
	 * does not endure as much cost in supplying a message string that is not used.  
	 * @param format a {@link String} format list as would be used to a printf() function, but
	 *  which must only specify {@code %s} {@link String} outputs.
	 * @param suppliers variable number of {@link Supplier}&lt;{@link String}&gt; arguments.  The
	 *  number must match the number of {@code %s} outputs in the format string. 
	 * @throws IOException upon problem with {@link Writer#append(CharSequence)} or
	 * {@link Writer#flush()}.
	 * @see #setEnabled(boolean)
	 */
	// We know this is @SafeVarags (or SuppressWarnings("unchecked")) on potential
	// "heap pollution" because we are only using the inputs as Objects.
	@SafeVarargs
	public static void message(String format, Supplier<String>... suppliers) throws IOException {
		if (!enabled) {
			return;
		}

		Object[] varArgs = new Object[suppliers.length];
		for (int i = 0; i < suppliers.length; i++) {
			Supplier<String> supplier = suppliers[i];
			String var = supplier.get().toString();
			varArgs[i] = var;
		}
		writer.append(String.format(format, varArgs));
		writer.append("\n");
		writer.flush();
	}

	/**
	 * Outputs a message to the PDB log if messaging has been enable, else ignored.  This method
	 * uses a {@link Supplier}&lt;{@link String}&gt; to allow for deferred processing of the message
	 * to output.  Thus, when message output is disabled, the client does not endure as much cost
	 * in supplying a message string that is not used.  
	 * @param supplier a {@link Supplier}&lt;{@link String}&gt; that supplies a {@link String}
	 * message to be output.
	 * @throws IOException upon problem with {@link Writer#append(CharSequence)} or
	 * {@link Writer#flush()}.
	 * @see #setEnabled(boolean)
	 */
	public static void message(Supplier<String> supplier) throws IOException {
		if (!enabled) {
			return;
		}

		writer.append(supplier.get());
		writer.append("\n");
		writer.flush();
	}

	/**
	 * Outputs a {@link String} message to the PDB log if messaging has been enable, else ignored.
	 * @param message a {@link String} message to be output.
	 * @throws IOException upon problem with {@link Writer#append(CharSequence)} or
	 * {@link Writer#flush()}.
	 * @see #setEnabled(boolean)
	 */
	public static void message(String message) throws IOException {
		writer.append(message);
		writer.append("\n");
		writer.flush();
	}

	/**
	 * Cleans up the class by closing resources.
	 * @throws IOException upon problem closing a {@link Writer}.
	 */
	public static void dispose() throws IOException {
		if (fileWriter != null) {
			fileWriter.close();
			fileWriter = null;
		}
	}

	/**
	 * Creates a {@link FileWriter} for the log file to which we are planning to write, and
	 *  deletes existing contents of the log file.
	 * @return a {@link FileWriter} for the log file.
	 */
	private static Writer createFileWriter() throws IOException {

		/*
		 * Since we want this logging to be used sparingly and on a case-by-case basis, we
		 * delete the log at the start of each JVM session.  New log writing always uses the
		 * same log file name with not date or process ID attributes.
		 */
		logFile = new File(Application.getUserSettingsDirectory(), "pdb.analyzer.log");
		if (logFile.exists()) {
			logFile.delete();
		}
		return new FileWriter(logFile);
	}
}
