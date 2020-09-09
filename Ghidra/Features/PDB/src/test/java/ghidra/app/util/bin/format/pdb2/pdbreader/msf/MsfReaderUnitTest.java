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
package ghidra.app.util.bin.format.pdb2.pdbreader.msf;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.*;
import java.util.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteWriter;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

public class MsfReaderUnitTest extends AbstractGenericTest {

	private static final int STREAM_OUTPUT_MAX = 0x80;

	// "Microsoft C/C++ program database 2.00\r\n" + (char) 0x1a + "JG";
	private static final byte[] IDENTIFICATION_200 =
		"Microsoft C/C++ program database 2.00\r\n\u001aJG".getBytes();
	// Padding between IDENTIFICATION and pageSize
	private static final byte[] padding200 = new byte[] { 0x00, 0x00 };

	// "Microsoft C/C++ MSF 7.00\r\n" + (char) 0x1a + "DS"
	private static final byte[] IDENTIFICATION_700 =
		"Microsoft C/C++ MSF 7.00\r\n\u001aDS".getBytes();
	// Padding between magic and pageSize
	private static final byte[] padding700 = new byte[] { 0x00, 0x00, 0x00 };

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected static File tDir;
	protected static String testFileName200;
	protected static File testFile200;
	protected static String testFileName700;
	protected static File testFile700;

	//==============================================================================================
	/**
	 * @throws IOException Upon file IO issues.
	 */
	@BeforeClass
	public static void setUp() throws IOException {
		tDir = createTempDirectory("msfreader");
		testFile200 = new File(tDir, "msfreader200.pdb");
		testFileName200 = testFile200.getAbsolutePath();
		byte[] buffer200 = createStreamFile200();
		FileOutputStream stream200 = new FileOutputStream(testFile200);
		stream200.write(buffer200);
		stream200.close();

		testFile700 = new File(tDir, "msfreader700.pdb");
		testFileName700 = testFile700.getAbsolutePath();
		byte[] buffer700 = createStreamFile700();
		FileOutputStream stream700 = new FileOutputStream(testFile700);
		stream700.write(buffer700);
		stream700.close();
	}

	@AfterClass
	public static void tearDown() throws Throwable {
		if (testFileName200 != null) {
			Msg.info(MsfReaderUnitTest.class, "MSF test file used: " + testFileName200);
		}
		if (testFileName700 != null) {
			Msg.info(MsfReaderUnitTest.class, "MSF test file used: " + testFileName700);
		}
	}

	//==============================================================================================
	/**
	 * Dumps a number bytes of information from a Stream in the AbstractStreamFile to String.
	 *  for debug purposes.
	 * @param streamFile The AbstractStreamFile to be used.
	 * @param streamNumber The streamNumber of the file to dump.
	 * @param maxOut Maximum number of bytes to dump.
	 * @return String containing the output.
	 */
	public static String dumpStream(AbstractMsf streamFile, int streamNumber, int maxOut) {
		MsfStream stream = streamFile.getStream(streamNumber);
		StringBuilder builder = new StringBuilder();
		builder.append("Stream: " + streamNumber + "\n");
		builder.append(stream.dump(maxOut));
		return builder.toString();
	}

	//==============================================================================================
	// Tests
	//==============================================================================================
	@Test
	public void testStreamFile200Header() {
		try (AbstractMsf streamFile =
			MsfParser.parse(testFileName200, new PdbReaderOptions(), TaskMonitor.DUMMY)) {
			int numStreams = streamFile.getNumStreams();
			StringBuilder builder = new StringBuilder();
			builder.append("NumStreams: " + numStreams + "\n");
			for (int streamNumber = 0; streamNumber < numStreams; streamNumber++) {
				builder.append(dumpStream(streamFile, streamNumber, STREAM_OUTPUT_MAX));
				builder.append("\n");
			}
			Msg.info(this, builder.toString());
		}
		catch (Exception e) {
			assertEquals(e.getClass(), FileNotFoundException.class);
		}
	}

	@Test
	public void testStreamFile700Header() {
		try (AbstractMsf streamFile =
			MsfParser.parse(testFileName700, new PdbReaderOptions(), TaskMonitor.DUMMY)) {
			int numStreams = streamFile.getNumStreams();
			StringBuilder builder = new StringBuilder();
			builder.append("NumStreams: " + numStreams + "\n");
			for (int streamNumber = 0; streamNumber < numStreams; streamNumber++) {
				builder.append(dumpStream(streamFile, streamNumber, STREAM_OUTPUT_MAX));
				builder.append("\n");
			}
			Msg.info(this, builder.toString());
		}
		catch (Exception e) {
			assertEquals(e.getClass(), FileNotFoundException.class);
		}
	}

	//==============================================================================================
	// Private Methods
	//==============================================================================================
	private static byte[] createStreamFile200() {
		int pageSize = 0x1000;
		MultiStreamFile msf200 = new MultiStreamFile(MsfVer.V200, pageSize);
		Stream stream = msf200.createStream();
		byte[] dataStreamBuffer = createDataForStream(pageSize);
		stream.putData(dataStreamBuffer);

		return msf200.serialize();
	}

	private static byte[] createStreamFile700() {
		int pageSize = 0x1000;
		MultiStreamFile msf700 = new MultiStreamFile(MsfVer.V700, pageSize);
		Stream stream = msf700.createStream();
		byte[] dataStreamBuffer = createDataForStream(pageSize);
		stream.putData(dataStreamBuffer);

		return msf700.serialize();
	}

	//==============================================================================================
	// Private Classes
	//==============================================================================================
	private static enum MsfVer {
		V200, V700
	}

	//==============================================================================================
	private static class MsfHeader {
		private MultiStreamFile msf;
		private List<Integer> serializationPageList;

		MsfHeader(MultiStreamFile msfSpec) {
			msf = msfSpec;
			serializationPageList = new ArrayList<>();
		}

		void init() {
			// By definition, header gets page 0.
			msf.fpm.reservePage(0);
			serializationPageList.add(0);
		}

		void serialize(int numPages, int fpmPn, byte[] directoryStreamInfoBytes) {
			byte[] bytes;
			if (msf.ver == MsfVer.V200) {
				bytes = createStreamFile200Header(msf.pageSize, fpmPn, numPages,
					directoryStreamInfoBytes);
			}
			else {
				bytes = createStreamFile700Header(msf.pageSize, fpmPn, numPages,
					directoryStreamInfoBytes);
			}
			msf.fillPages(bytes, serializationPageList);
		}

		private byte[] createStreamFile200Header(int pageSize, int freePageMapPageNumber,
				int numPages, byte[] directoryStreamInfo) {
			if (pageSize != 0x400 && pageSize != 0x800 && pageSize != 0x1000) {
				return null;
			}
			if (freePageMapPageNumber < 1 || freePageMapPageNumber > 0xffff) {
				return null;
			}
			if (numPages < 1 || numPages > 0xffff) {
				return null;
			}
			PdbByteWriter writer = new PdbByteWriter();
			writer.putBytes(IDENTIFICATION_200);
			writer.putBytes(padding200);
			writer.putInt(pageSize);
			writer.putUnsignedShort(freePageMapPageNumber);
			writer.putUnsignedShort(numPages);
			writer.putBytes(directoryStreamInfo);
			return writer.get();
		}

		private byte[] createStreamFile700Header(int pageSize, int freePageMapPageNumber,
				int numPages, byte[] directoryStreamInfo) {
			if (pageSize != 0x200 && pageSize != 0x400 && pageSize != 0x800 && pageSize != 0x1000) {
				return null;
			}
			if (freePageMapPageNumber < 1) { // not checking upper limit
				return null;
			}
			if (numPages < 1) { // not checking upper limit
				return null;
			}
			PdbByteWriter writer = new PdbByteWriter();
			writer.putBytes(IDENTIFICATION_700);
			writer.putBytes(padding700);
			writer.putInt(pageSize);
			writer.putInt(freePageMapPageNumber);
			writer.putInt(numPages);
			writer.putBytes(directoryStreamInfo);
			return writer.get();
		}

	}

	//==============================================================================================
	private static class FreePageMap {
		private MultiStreamFile msf;
		private List<Integer> serializationPageList;
		// numUsedPages not used, but would be if we allowed it fpm to grow or allowed modification
		//  model, in which case we would need to search the list first before adding to the list.
		//  Having the value could short-cut the need for searching.
		//private int numUsedPages;
		boolean[] freePage;

		FreePageMap(MultiStreamFile msfSpec) {
			msf = msfSpec;
			serializationPageList = new ArrayList<>();
			//numUsedPages = 0;
			freePage = new boolean[msf.totalPages];
			for (int i = 0; i < msf.totalPages; i++) {
				freePage[i] = true;
			}
		}

		void init() {
			// Taking page 1 for FreePageMap.
			reservePage(1);
			serializationPageList.add(1);
		}

		void reservePage(int pageNumber) {
			if (!freePage[pageNumber]) {
				fail("Page already free... terminating");
			}
			freePage[pageNumber] = false;
		}

		List<Integer> reservePages(int dataLength) {
			int numPages = 1 + (dataLength - 1) / msf.pageSize;
			List<Integer> pageList = new ArrayList<>();
			for (int i = 0; i < numPages; i++) {
				pageList.add(msf.fpm.getFreePage());
			}
			return pageList;
		}

		void serialize() {
			byte[] bytes;
			if (msf.ver == MsfVer.V200) {
				bytes = serializedFreePageMap200();
			}
			else {
				bytes = serializedFreePageMap700();
			}
			msf.fillPages(bytes, serializationPageList);
		}

		private int getFreePage() {
			for (int i = 0; i < freePage.length; i++) {
				if (freePage[i]) {
					freePage[i] = false;
					//numUsedPages++;
					return i;
				}
			}
			String msg = "Unexpected algorithm flow";
			Msg.error(null, msg);
			throw new AssertException(msg);
		}

		private byte[] serializedFreePageMap200() {
			// TODO: detailed work.
			int bits = 0x00;
			PdbByteWriter writer = new PdbByteWriter();
			writer.putUnsignedByte(bits);
			return writer.get();
		}

		private byte[] serializedFreePageMap700() {
			// TODO: detailed work.
			int bits = 0x00;
			PdbByteWriter writer = new PdbByteWriter();
			writer.putUnsignedByte(bits);
			return writer.get();
		}
	}

	//==============================================================================================
	private static class Stream {
		MultiStreamFile msf;
		int streamNum;
		private List<Integer> serializationPageList;
		private byte[] data;

		Stream(MultiStreamFile msfSpec) {
			msf = msfSpec;
			serializationPageList = new ArrayList<>();
			streamNum = msf.st.addStream(this);
			data = new byte[0];
		}

		void serialize() {
			msf.fillPages(data, serializationPageList);
		}

		byte[] serializeStreamInfo() {
			PdbByteWriter writer = new PdbByteWriter();
			writer.putBytes(serializeLengthAndMapTableAddress());
			writer.putBytes(serializePageNumbers());
			return writer.get();
		}

		// Not supporting incremental writing.
		void putData(byte[] dataIn) {
			data = dataIn;
			serializationPageList = msf.fpm.reservePages(data.length);
		}

//		int getLength() {
//			return data.length;
//		}
//
//		byte[] getData() {
//			return data;
//		}
//
		protected byte[] serializeLength() {
			PdbByteWriter writer = new PdbByteWriter();
			writer.putInt(data.length);
			return writer.get();
		}

		protected byte[] serializeLengthAndMapTableAddress() {
			PdbByteWriter writer = new PdbByteWriter();
			writer.putInt(data.length);
			writer.putInt(0); // MapTable address?
			return writer.get();
		}

		protected byte[] serializePageNumbers() {
			if (msf.ver == MsfVer.V200) {
				return serializePageNumbers200(serializationPageList);
			}
			return serializePageNumbers700(serializationPageList);
		}

		protected byte[] serializePageNumbers200(List<Integer> pageList) {
			PdbByteWriter writer = new PdbByteWriter();
			for (int page : pageList) {
				writer.putUnsignedShort(page);
			}
			return writer.get();
		}

		protected byte[] serializePageNumbers700(List<Integer> pageList) {
			PdbByteWriter writer = new PdbByteWriter();
			for (int page : pageList) {
				writer.putInt(page);
			}
			return writer.get();
		}
	}

	//==============================================================================================
	private static class DirectoryStream extends Stream {

		List<Integer> superSerializationPageList;
		byte[] superData;

		DirectoryStream(MultiStreamFile msfSpec) {
			super(msfSpec);
			superSerializationPageList = new ArrayList<>();
			superData = new byte[0];
		}

		@Override
		void putData(byte[] dataIn) {
			superData = dataIn;
			superSerializationPageList = msf.fpm.reservePages(superData.length);
			super.putData(serializePageNumbers700(superSerializationPageList));
		}

		@Override
		void serialize() {
			msf.fillPages(superData, superSerializationPageList);
			super.serialize();
		}

		@Override
		protected byte[] serializeLength() {
			PdbByteWriter writer = new PdbByteWriter();
			writer.putInt(superData.length);
			return writer.get();
		}

		@Override
		protected byte[] serializeLengthAndMapTableAddress() {
			PdbByteWriter writer = new PdbByteWriter();
			writer.putInt(superData.length);
			writer.putInt(0); // MapTable address?
			return writer.get();
		}

	}

	//==============================================================================================
	private static class StreamTable {
		MultiStreamFile msf;
		int nextStreamNum;
		List<Integer> streamNumbers;
		Map<Integer, Stream> streamMap;

		StreamTable(MultiStreamFile msfSpec) {
			msf = msfSpec;
			nextStreamNum = 0;
			streamNumbers = new ArrayList<>();
			streamMap = new HashMap<>();
		}

		void init() {
			// nothing at the moment
		}

		int addStream(Stream stream) {
			streamMap.put(nextStreamNum, stream);
			streamNumbers.add(nextStreamNum);
			return nextStreamNum++;
		}

		List<Integer> getStreamNumbers() {
			return streamNumbers;
		}

		Stream getStream(int streamNumber) {
			return streamMap.get(streamNumber);
		}

		byte[] serialize() {
			PdbByteWriter writer = new PdbByteWriter();
			writer.putInt(streamMap.size());
			if (msf.ver == MsfVer.V200) {
				for (int streamNumber : streamMap.keySet()) {
					Stream stream = streamMap.get(streamNumber);
					writer.putBytes(stream.serializeLengthAndMapTableAddress());
				}
			}
			else {
				for (int streamNumber : streamMap.keySet()) {
					Stream stream = streamMap.get(streamNumber);
					writer.putBytes(stream.serializeLength());
				}
			}

			for (int streamNumber : streamMap.keySet()) {
				Stream stream = streamMap.get(streamNumber);
				writer.putBytes(stream.serializePageNumbers());
			}
			return writer.get();
		}
	}

	//==============================================================================================
	private static class MultiStreamFile {
		private MsfVer ver;
		private int pageSize;
		private MsfHeader header;
		private FreePageMap fpm;
		private StreamTable st;
		private Stream ds;
		private int totalPages = 0x20; // Doing a fixed size.
		private byte[] outputBuffer;

		MultiStreamFile(MsfVer verSpec, int pageSizeSpec) {
			ver = verSpec;
			pageSize = pageSizeSpec;
			header = new MsfHeader(this);
			fpm = new FreePageMap(this);
			st = new StreamTable(this);
			if (ver == MsfVer.V200) {
				ds = new Stream(this);
			}
			else {
				ds = new DirectoryStream(this);
			}
			if (ds.streamNum != 0) {
				String msg = "Stream 0 expected... terminating";
				Msg.error(null, msg);
				throw new AssertException(msg);
			}
			header.init();
			fpm.init();
			st.init();
		}

		Stream createStream() {
			return new Stream(this);
		}

//		Strm getStream(int streamNumber) {
//			return st.getStream(streamNumber);
//		}
//
		byte[] serialize() {
			outputBuffer = new byte[pageSize * totalPages];
			ds.putData(st.serialize());
			fpm.serialize();
			for (int streamNumber : st.getStreamNumbers()) {
				Stream stream = st.getStream(streamNumber);
				stream.serialize();
			}
			header.serialize(totalPages, fpm.serializationPageList.get(0),
				ds.serializeStreamInfo());
			return outputBuffer;
		}

		void fillPages(byte[] inputBuffer, List<Integer> pageList) {
			if (outputBuffer == null) {
				String msg = "Output buffer is null... terminating";
				Msg.error(null, msg);
				throw new AssertException(msg);
			}
			if (pageList.size() <= 0) {
				String msg = "Invalid page list size... terminating";
				Msg.error(null, msg);
				throw new AssertException(msg);
			}
			int outputIndex;
			int inputIndex = 0;
			for (int i = 0; i < pageList.size() - 1; i++) {
				outputIndex = pageSize * pageList.get(i);
				for (int j = 0; j < pageSize; j++) {
					outputBuffer[outputIndex++] = inputBuffer[inputIndex++];
				}
			}
			outputIndex = pageSize * pageList.get(pageList.size() - 1);
			int numRemaining = inputBuffer.length - inputIndex;
			int j;
			for (j = 0; j < numRemaining; j++) {
				outputBuffer[outputIndex++] = inputBuffer[inputIndex++];
			}
			for (j = numRemaining; j < pageSize; j++) {
				outputBuffer[outputIndex++] = 0x00;
			}
		}

	}

	//==============================================================================================
	// Junk/test data for a data stream.
	private static byte[] createDataForStream(int pageSize) {
		PdbByteWriter writer = new PdbByteWriter();
		for (int i = 0; i < 16; i++) {
			writer.putUnsignedByte(0x55);
			writer.putUnsignedByte(0xaa);
		}
		for (int i = 0; i < 16; i++) {
			writer.putUnsignedShort(0x1111);
			writer.putUnsignedShort(0xeeee);
		}
		return writer.get();
	}
}
