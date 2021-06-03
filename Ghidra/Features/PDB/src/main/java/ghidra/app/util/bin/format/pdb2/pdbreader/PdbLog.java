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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.*;
import java.util.function.Supplier;

import generic.io.NullWriter;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * A utility class providing logging for: PDB parsing and PDB analysis.  It includes data and
 * metrics for the purposes of debugging and aiding in continued research and development of
 * this package.
 */
public class PdbLog {

	private static Writer nullWriter;
	private static Writer fileWriter;
	private static final boolean SYSTEM_LOGGING_ENABLED = Boolean.getBoolean("pdb.logging");
	private static boolean enabled = SYSTEM_LOGGING_ENABLED;

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
	 * @see #setEnabled(boolean)
	 */
	// We know this is @SafeVarags (or SuppressWarnings("unchecked")) on potential
	// "heap pollution" because we are only using the inputs as Objects.
	@SafeVarargs
	public static void message(String format, Supplier<String>... suppliers) {
		if (!enabled) {
			return;
		}

		Object[] varArgs = new Object[suppliers.length];
		for (int i = 0; i < suppliers.length; i++) {
			Supplier<String> supplier = suppliers[i];
			String var = supplier.get().toString();
			varArgs[i] = var;
		}
		try {
			Writer writer = getWriter();
			writer.append(String.format(format, varArgs));
			writer.append("\n");
			writer.flush();
		}
		catch (IOException e) {
			handleIOException(e);
		}
	}

	/**
	 * Outputs a message to the PDB log if messaging has been enable, else ignored.  This method
	 * uses a {@link Supplier}&lt;{@link String}&gt; to allow for deferred processing of the message
	 * to output.  Thus, when message output is disabled, the client does not endure as much cost
	 * in supplying a message string that is not used.
	 * @param supplier a {@link Supplier}&lt;{@link String}&gt; that supplies a {@link String}
	 * message to be output.
	 * @see #setEnabled(boolean)
	 */
	public static void message(Supplier<String> supplier) {
		if (!enabled) {
			return;
		}

		try {
			Writer writer = getWriter();
			writer.append(supplier.get());
			writer.append("\n");
			writer.flush();
		}
		catch (IOException e) {
			handleIOException(e);
		}
	}

	/**
	 * Outputs a {@link String} message to the PDB log if messaging has been enable, else ignored.
	 * @param message a {@link String} message to be output.
	 * @see #setEnabled(boolean)
	 */
	public static void message(String message) {
		try {
			Writer writer = getWriter();
			writer.append(message);
			writer.append("\n");
			writer.flush();
		}
		catch (IOException e) {
			handleIOException(e);
		}
	}

	public static void logSerializationItemClassMismatch(IdMsParsable parsable,
			Class<?> requiredClass, int dataTypeId) {
		message("Parsed type (" + parsable.getClass().getSimpleName() +
			") does not matched required (" + requiredClass.getSimpleName() + ") for dataTypeId " +
			dataTypeId);
	}

	public static void logDeserializationFailure(PdbByteReader reader, int dataTypeId,
			Exception e) {
		message("Encountered exception on dataTypeId " + dataTypeId + " near reader index " +
			reader.getIndex() + ": " + e);
	}

	// TODO: Not sure if we will keep this.  It is recording "on-use" detection instead of
	//  "when-parsed" detection.  Not sure if when-parsed detection can work as the min/max
	//  might not have been read, depending on the order of how record sets are read.
	// TODO: is using PdbLog here.  Is that what we intend?
	/**
	 * Logs fact of record index out of range (detection is performed by caller).
	 * @param tpi the TypeProgramInterface involved.
	 * @param recordNumber the record number to report.
	 */
	public static void logBadTypeRecordIndex(AbstractTypeProgramInterface tpi, int recordNumber) {
		message("Bad requested type record " + recordNumber + ", min: " + tpi.getTypeIndexMin() +
			", max: " + tpi.getTypeIndexMaxExclusive());
	}

	/**
	 * Logs fact of record index out of range (detection is performed by caller).
	 * @param type {@link AbstractMsType} found
	 * @param itemRequiredClass class expected
	 */
	public static void logGetTypeClassMismatch(AbstractMsType type, Class<?> itemRequiredClass) {
		message("Mismatch type  " + type.getClass().getSimpleName() + " for " + type.getName() +
			", expected: " + itemRequiredClass.getSimpleName());
	}

	/**
	 * Cleans up the class by closing resources.
	 */
	public static void dispose() {
		try {
			if (fileWriter != null) {
				fileWriter.close();
			}
		}
		catch (IOException newException) {
			// squash
		}
		fileWriter = null;
	}

	/**
	 * Returns the {@link Writer} for logging.
	 * @return a {@link Writer} for for logging.
	 */
	private static Writer getWriter() throws IOException {
		return enabled ? getFileWriter() : getNullWriter();
	}

	/**
	 * Returns the {@link FileWriter} for the log file.  If the file is already open, it is
	 * returned.  If not already open, it is opened and previous contents are deleted.
	 * @return a {@link FileWriter} for the log file.
	 */
	private static Writer getFileWriter() throws IOException {
		if (fileWriter == null) {
			/*
			 * Since we want this logging to be used sparingly and on a case-by-case basis, we
			 * delete the log contents upon initial opening.  New log writing always uses the
			 * same log file name with not date or process ID attributes.
			 */
			File logFile = new File(Application.getUserSettingsDirectory(), "pdb.analyzer.log");
			if (logFile.exists()) {
				logFile.delete();
			}
			fileWriter = new FileWriter(logFile);
		}
		return fileWriter;
	}

	/**
	 * Returns a {@link NullWriter} for the log file when chosen instead of a FileWriter.  If
	 * one already exists, it is returned.  Otherwise a new one is created.
	 * @return a {@link NullWriter} for the log file.
	 */
	private static Writer getNullWriter() {
		if (nullWriter == null) {
			nullWriter = new NullWriter();
		}
		return nullWriter;
	}

	private static void handleIOException(IOException exception) {
		try {
			if (fileWriter != null) {
				fileWriter.close();
			}
		}
		catch (IOException newException) {
			// squash
		}
		Msg.error(PdbLog.class, "IOException encountered; disabling writer", exception);
		enabled = false;
	}

}
