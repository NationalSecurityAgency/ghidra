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
package ghidra.program.examiner;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.GhidraException;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.core.analysis.EmbeddedMediaAnalyzer;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import utility.application.ApplicationLayout;

/**
 * Wrapper for Ghidra code to find images (and maybe other artifacts later) in a program
 * 
 * NOTE: This is intended for end-user use and has no direct references within Ghidra.  
 * Typical use of the class entails generating a ghidra.jar (see BuildGhidraJarScript.java)
 * and referencing this class from end-user code.
 */
public class ProgramExaminer {

	private MessageLog messageLog;
	private Program program;

	private static Language defaultLanguage;

	/**
	 * Constructs a new ProgramExaminer.
	 * @param bytes the bytes of the potential program to be examined.
	 * @throws GhidraException if any exception occurs while processing the bytes.
	 */
	public ProgramExaminer(byte[] bytes) throws GhidraException {
		this(createByteProvider(bytes));
	}

	/**
	 * Constructs a new ProgramExaminer.
	 * @param file file object containing the bytes to be examined.
	 * @throws GhidraException if any exception occurs while processing the bytes.
	 */
	public ProgramExaminer(File file) throws GhidraException {
		this(createByteProvider(file));
	}

	/**
	 * Returns a string indication the program format. i.e. PE, elf, raw
	 */
	public String getType() {
		return program.getExecutableFormat();
	}

	private ProgramExaminer(ByteProvider provider) throws GhidraException {
		initializeGhidra();
		messageLog = new MessageLog();
		try {
			program = AutoImporter.importByUsingBestGuess(provider, null, this, messageLog,
				TaskMonitorAdapter.DUMMY_MONITOR);

			if (program == null) {
				program = AutoImporter.importAsBinary(provider, null, defaultLanguage, null, this,
					messageLog, TaskMonitorAdapter.DUMMY_MONITOR);
			}
			if (program == null) {
				throw new GhidraException(
					"Can't create program from input: " + messageLog.toString());
			}
		}
		catch (Exception e) {
			messageLog.appendException(e);
			throw new GhidraException(e);
		}
		finally {
			try {
				provider.close();
			}
			catch (IOException e) {
				// tried to close
			}
		}
	}

	public synchronized static void initializeGhidra() throws GhidraException {
		if (!Application.isInitialized()) {
			ApplicationLayout layout;
			try {
				layout =
					new GhidraTestApplicationLayout(new File(System.getProperty("java.io.tmpdir")));
			}
			catch (IOException e) {
				throw new GhidraException(e);
			}
			HeadlessGhidraApplicationConfiguration config =
				new HeadlessGhidraApplicationConfiguration();
			config.setInitializeLogging(false);
			Application.initializeApplication(layout, config);
		}
		if (defaultLanguage == null) {
			LanguageService languageService = DefaultLanguageService.getLanguageService();
			try {
				defaultLanguage = languageService
						.getDefaultLanguage(Processor.findOrPossiblyCreateProcessor("DATA"));
			}
			catch (LanguageNotFoundException e) {
				throw new GhidraException("Can't load default language: DATA");
			}
		}
	}

	/**
	 * Releases file/database resources.
	 */
	public void dispose() {
		program.release(this);
	}

	/**
	 * Returns a list of byte[] containing image data.  The bytes will be either a png, a gif, or
	 * a bitmap
	 */
	public List<byte[]> getImages() {
		runImageAnalyzer();

		List<byte[]> imageList = new ArrayList<byte[]>();
		DataIterator it = program.getListing().getDefinedData(true);
		while (it.hasNext()) {
			accumulateImageData(imageList, it.next());
		}
		return imageList;
	}

	private void accumulateImageData(List<byte[]> imageList, Data data) {
		if (!isImage(data)) {
			return;
		}

		try {
			imageList.add(data.getBytes());
		}
		catch (MemoryAccessException e) {
			// suppress (this shouldn't happen
		}
	}

	private void runImageAnalyzer() {
		int txID = program.startTransaction("find images");
		try {
			EmbeddedMediaAnalyzer imageAnalyzer = new EmbeddedMediaAnalyzer();
			imageAnalyzer.added(program, program.getMemory(), TaskMonitorAdapter.DUMMY_MONITOR,
				messageLog);
		}
		catch (CancelledException e) {
			// using Dummy, can't happen
		}
		finally {
			program.endTransaction(txID, true);
		}
	}

	private boolean isImage(Data data) {
		DataType dataType = data.getDataType();
		if (dataType instanceof PngDataType) {
			return true;
		}
		if (dataType instanceof GifDataType) {
			return true;
		}
		if (dataType instanceof BitmapResourceDataType) {
			return true;
		}
		if (dataType instanceof IconResourceDataType) {
			return true;
		}
		if (dataType instanceof JPEGDataType) {
			return true;
		}
		return false;
	}

//==================================================================================================
// static methods
//==================================================================================================

	private static ByteProvider createByteProvider(byte[] bytes) throws GhidraException {
		if (bytes == null) {
			throw new GhidraException("Attempted to process a null byte[].");
		}
		if (bytes.length == 0) {
			throw new GhidraException("Attempted to process an empty byte[].");
		}
		return new ByteArrayProvider("Bytes", bytes);
	}

	private static ByteProvider createByteProvider(File file) throws GhidraException {
		if (file == null) {
			throw new GhidraException("Attempted to process a null file");
		}
		try {
			return new RandomAccessByteProvider(file);
		}
		catch (IOException e) {
			throw new GhidraException(e);
		}
	}

}
