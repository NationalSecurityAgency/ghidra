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
package ghidra.app.decompiler;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

/**
 *
 *
 * Class for communicating with a single decompiler process.
 * The process controls decompilation for a single Program.
 * The process is initiated by the registerProgram method.
 * If the process is ready, the statusGood flag will be set
 * to true.  This flag must be checked via the isReady method
 * prior to invoking any of the public methods.  If the
 * process isn't ready, the only way to recover is by
 * reissuing the registerProgram call and making any other
 * necessary initialization calls.
 */

public class DecompileProcess {

	//	public static DecompileProcess decompProcess = null;
	private final static byte[] command_start = { 0, 0, 1, 2 };
	private final static byte[] command_end = { 0, 0, 1, 3 };
	private final static byte[] query_response_start = { 0, 0, 1, 8 };
	private final static byte[] query_response_end = { 0, 0, 1, 9 };
	private final static byte[] string_start = { 0, 0, 1, 14 };
	private final static byte[] string_end = { 0, 0, 1, 15 };
	private final static byte[] exception_start = { 0, 0, 1, 10 };
	private final static byte[] exception_end = { 0, 0, 1, 11 };
	private final static byte[] byte_start = { 0, 0, 1, 12 };
	private final static byte[] byte_end = { 0, 0, 1, 13 };

	//private static final int MAXIMUM_RESULT_SIZE = 50 * 1024 * 1024; // maximum result size in bytes to allow from decompiler

	private Runtime runtime = Runtime.getRuntime();
	private String[] exepath; // Path to the decompiler executable
	private Runnable timeoutRunnable;

	// Note: volatile for variables modified when we shutdown, potential from different thread
	private volatile Process nativeProcess;
	private volatile InputStream nativeIn;   // Input from decompiler
	private volatile OutputStream nativeOut; // Output to decompiler
	private volatile boolean statusGood;     // true if decompiler process is running

	private int archId = -1;              // architecture id for decomp process
	private DecompileCallback callback;   // Callback interface for decompiler
	private String programSource;		// String describing program for error reports
	private int maxResultSizeMBYtes = 50; // maximum result size in MBytes to allow from decompiler

	private PackedDecode paramDecoder;			// Decoder to use for queries from the decompiler
	private PackedEncode resultEncoder;			// Encoder to use for query responses
	private StringIngest stringDecoder;		// Ingest of exception and status messages

	public enum DisposeState {
		NOT_DISPOSED,        // Process was/is not disposed
		DISPOSED_ON_TIMEOUT, // A timeout occurred
		DISPOSED_ON_CANCEL, // The process was cancelled
		DISPOSED_ON_STARTUP_FAILURE // The executable failed to start
	}

	private volatile DisposeState disposestate = DisposeState.NOT_DISPOSED; // How this process was (or was not) disposed

	public DecompileProcess(String path) {

		exepath = new String[] { path };
//		exepath = new String[] { "/usr/bin/valgrind", "--tool=memcheck", "--leak-check=yes", "--track-origins=yes", "--error-limit=no", "--log-file=/tmp/decompvalgrindout%p.txt", path };

		timeoutRunnable = new Runnable() {
			@Override
			public void run() {
				dispose();
				disposestate = DisposeState.DISPOSED_ON_TIMEOUT;
			}
		};
		stringDecoder = new StringIngest();
	}

	public void dispose() {
		if (disposestate != DisposeState.NOT_DISPOSED) {
			return;
		}

		disposestate = DisposeState.DISPOSED_ON_CANCEL;
		statusGood = false;

		// Disposing sometimes hangs and we don't want to hang the swing thread.
		DecompilerDisposer.dispose(nativeProcess, nativeOut, nativeIn);
	}

	public DisposeState getDisposeState() {
		return disposestate;
	}

	private void setup() throws IOException {
		if (disposestate != DisposeState.NOT_DISPOSED) {
			throw new IOException("Decompiler has been disposed");
		}
		if (nativeProcess != null) {
			// Something bad happened to the process or the interface
			// and now we try to restart
			nativeProcess.destroy(); // Make sure previous bad process is killed           			
			nativeProcess = null;
		}
		if (exepath == null || exepath.length == 0 || exepath[0] == null) {
			throw new IOException("Could not find decompiler executable");
		}
		try {
			nativeProcess = runtime.exec(exepath);

			nativeIn = nativeProcess.getInputStream();
			nativeOut = nativeProcess.getOutputStream();
			statusGood = true;
		}
		catch (IOException e) {
			disposestate = DisposeState.DISPOSED_ON_STARTUP_FAILURE;
			statusGood = false;
			Msg.showError(this, null, "Problem launching decompiler",
				"Please report this stack trace to the Ghidra Team", e);
			throw e;
		}
	}

	private int readToBurst() throws IOException {
		if (nativeIn == null) {
			// we've been disposed!
			// (not sure if throwing an exception the best)
			throw new IOException("Decompiler disposed!");
		}

		int cur;
		for (;;) {
			do {
				cur = nativeIn.read();
			}
			while (cur > 0);
			if (cur == -1) {
				break;
			}
			do {
				cur = nativeIn.read();
			}
			while (cur == 0);
			if (cur == 1) {
				cur = nativeIn.read();
				if (cur == -1) {
					break;
				}
				return cur;
			}
			if (cur == -1) {
				break;
			}
		}
		throw new IOException("Decompiler process died");
	}

	private void readToResponse() throws IOException, DecompileException {
		nativeOut.flush(); // Make sure decompiler has access to all the info it has been sent
		int type;
		do {
			type = readToBurst();
		}
		while ((type & 1) == 1);
		if (type == 10) {
			generateException();
		}
		if (type == 6) {
			return;
		}
		throw new IOException("Ghidra/decompiler alignment error");
	}

	private int readToBuffer(ByteIngest buf) throws IOException {
		int cur;
		for (;;) {
			buf.ingestStream(nativeIn);
			do {
				cur = nativeIn.read();
			}
			while (cur == 0);
			if (cur == 1) {
				cur = nativeIn.read();
				if (cur > 0) {
					return cur;
				}
			}
			if (cur == -1) {
				break;
			}
		}
		throw new IOException("Decompiler process died");
	}

	private void readQueryParam(ByteIngest ingester) throws IOException {
		int type = readToBurst();
		if (type != 14) {
			throw new IOException("GHIDRA/decompiler alignment error");
		}
		ingester.open(1 << 16, programSource);
		type = readToBuffer(ingester);
		if (type != 15) {
			throw new IOException("GHIDRA/decompiler alignment error");
		}
		ingester.endIngest();
	}

	private void writeString(String msg) throws IOException {
		write(string_start);
		write(msg.getBytes());
		write(string_end);
	}

	private void writeString(Encoder byteResult) throws IOException {
		if (nativeOut == null) {
			return;
		}
		write(string_start);
		byteResult.writeTo(nativeOut);
		write(string_end);
	}

	private void generateException() throws IOException, DecompileException {
		readQueryParam(stringDecoder);
		String type = stringDecoder.toString();
		readQueryParam(stringDecoder);
		String message = stringDecoder.toString();
		readToBurst(); // Read exception terminator
		if (type.equals("alignment")) {
			throw new IOException("Alignment error: " + message);
		}
		throw new DecompileException(type, message);
	}

	private void readResponse(ByteIngest mainResponse) throws IOException, DecompileException {
		mainResponse.clear();
		readToResponse();
		int type = readToBurst();
		int commandId;
		ByteIngest currentResponse = null;

		while (type != 7) {
			switch (type) {
				case 4:
					readQueryParam(paramDecoder);
					try {
						commandId = paramDecoder.openElement();
						switch (commandId) {
							case COMMAND_ISNAMEUSED:
								isNameUsed();
								break;
							case COMMAND_GETBYTES:
								getBytes();						// getBytes
								break;
							case COMMAND_GETCOMMENTS:
								getComments();
								break;
							case COMMAND_GETCALLFIXUP:
								getPcodeInject(InjectPayload.CALLFIXUP_TYPE);
								break;
							case COMMAND_GETCALLOTHERFIXUP:
								getPcodeInject(InjectPayload.CALLOTHERFIXUP_TYPE);
								break;
							case COMMAND_GETCALLMECH:
								getPcodeInject(InjectPayload.CALLMECHANISM_TYPE);
								break;
							case COMMAND_GETPCODEEXECUTABLE:
								getPcodeInject(InjectPayload.EXECUTABLEPCODE_TYPE);
								break;
							case COMMAND_GETCPOOLREF:
								getCPoolRef();
								break;
							case COMMAND_GETEXTERNALREF:
								getExternalRef();
								break;
							case COMMAND_GETMAPPEDSYMBOLS:
								getMappedSymbols();
								break;
							case COMMAND_GETNAMESPACEPATH:
								getNamespacePath();
								break;
							case COMMAND_GETPCODE:
								getPcode();
								break;
							case COMMAND_GETREGISTER:
								getRegister();
								break;
							case COMMAND_GETREGISTERNAME:
								getRegisterName();
								break;
							case COMMAND_GETSTRINGDATA:
								getStringData();
								break;
							case COMMAND_GETCODELABEL:
								getCodeLabel();
								break;
							case COMMAND_GETDATATYPE:
								getDataType();
								break;
							case COMMAND_GETTRACKEDREGISTERS:
								getTrackedRegisters();
								break;
							case COMMAND_GETUSEROPNAME:
								getUserOpName();
								break;
							default:
								throw new Exception("Unsupported decompiler query");
						}
					}
					catch (Exception e) { // Catch ANY exception query generates
						// and pass it down to decompiler
						write(exception_start);
						String extype = e.getClass().getName();
						String msg = e.getMessage();
						if (msg == null) {
							msg = "";
						}
						writeString(extype);
						writeString(msg);
						write(exception_end);

						if (disposestate == DisposeState.NOT_DISPOSED) {
							Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
						}
					}
					nativeOut.flush(); // Make sure decompiler receives response
					readToBurst(); // Read query terminator
					break;
				case 6:
					throw new IOException("GHIDRA/decompiler out of alignment");
				case 10:
					generateException();
					break;
				case 14:			// Start of the main decompiler output
					if (currentResponse != null) {
						throw new IOException("Nested decompiler output");
					}
					// Allocate storage buffer for the result, which is generally not tiny. So we
					// start with any initial allocation of 1024 bytes, also give an absolute upper bound
					// determined by maxResultSizeMBYtes
					currentResponse = mainResponse;
					currentResponse.open(maxResultSizeMBYtes << 20, programSource);
					break;
				case 15:			// This is the end of the main decompiler output
					if (currentResponse == null) {
						throw new IOException("Mismatched string header");
					}
					currentResponse.endIngest();
					currentResponse = null;		// Reset current buffer as a native message may follow
					break;
				case 16:			// Beginning of any native message from the decompiler
					if (currentResponse != null) {	// Beginning of native message before end of main response
						currentResponse.clear();	// Don't try to parse main response
					}
					currentResponse = stringDecoder;
					currentResponse.open(1 << 20, programSource);
					break;
				case 17:			// End of the native message from the decompiler
					if (currentResponse == null) {
						throw new IOException("Mismatched message header");
					}
					currentResponse.endIngest();
					callback.setNativeMessage(currentResponse.toString());
					currentResponse = null;
					break;
				default:
					throw new IOException("GHIDRA/decompiler alignment error");

			}
			if (currentResponse == null) {
				type = readToBurst();
			}
			else {
				type = readToBuffer(currentResponse);
			}
		}
	}

	// Calls to the decompiler

	/**
	 * Initialize decompiler for a particular platform
	 * @param cback = callback object for decompiler
	 * @param pspecxml = string containing .pspec xml
	 * @param cspecxml = string containing .cspec xml
	 * @param tspecxml = XML string containing translator spec
	 * @param coretypesxml = XML description of core data-types
	 * @param program is the program being registered
	 * @throws IOException for problems with the pipe to the decompiler process
	 * @throws DecompileException for problems executing the command
	 */
	public synchronized void registerProgram(DecompileCallback cback, String pspecxml,
			String cspecxml, String tspecxml, String coretypesxml, Program program)
			throws IOException, DecompileException {
		callback = cback;
		programSource = program.getName();

		// Decompiler process may callback during the registerProgram operation
		// so provide query/reponse decoding/encoding
		paramDecoder = new PackedDecode(program.getAddressFactory());
		resultEncoder = new PackedEncode();

		StringIngest response = new StringIngest();	// Don't use stringDecoder

		setup();
		try {
			write(command_start);
			writeString("registerProgram");
			writeString(pspecxml);
			writeString(cspecxml);
			writeString(tspecxml);
			writeString(coretypesxml);
			write(command_end);
			readResponse(response);
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
		archId = Integer.parseInt(response.toString());
	}

	/**
	 * Free decompiler resources
	 * @return 1 if a program was actively deregistered, 0 otherwise
	 * @throws IOException for problems with the pipe to the decompiler
	 * @throws DecompileException for problems executing the command
	 */
	public synchronized int deregisterProgram() throws IOException, DecompileException {
		if (!statusGood) {
			throw new IOException("deregisterProgram called on bad process");
		}
		// Once a program is deregistered, the process is never
		// used again
		statusGood = false;
		write(command_start);
		writeString("deregisterProgram");
		writeString(Integer.toString(archId));
		write(command_end);
		paramDecoder = null;		// Don't expect callback queries
		resultEncoder = null;
		StringIngest response = new StringIngest();		// Don't use stringResponse
		readResponse(response);
		int res = Integer.parseInt(response.toString());
		callback = null;
		programSource = null;
		paramDecoder = null;
		resultEncoder = null;
		return res;
	}

	/**
	 * Send a single command to the decompiler with no parameters and return response
	 * @param command is the name of the command to execute
	 * @param response the response accumulator
	 * @throws IOException for any problems with the pipe to the decompiler process
	 * @throws DecompileException for any problems executing the command
	 */
	public synchronized void sendCommand(String command, ByteIngest response)
			throws IOException, DecompileException {
		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}
		paramDecoder = null;	// Don't expect callback queries
		resultEncoder = null;
		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			write(command_end);
			readResponse(response);
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
	}

	public synchronized boolean isReady() {
		return statusGood;
	}

	/**
	 * Execute a command with a timeout.  Parameters are in the encodingSet.mainQuery.
	 * The response gets written to encodingSet.mainResponse.  
	 * @param command the decompiler should execute
	 * @param timeoutSecs the number of seconds to run before timing out
	 * @param encodeSet contains encoded parameters and the response container
	 * @throws IOException for any problems with the pipe to the decompiler process
	 * @throws DecompileException for any problems while executing the command
	 */
	public synchronized void sendCommandTimeout(String command, int timeoutSecs,
			DecompInterface.EncodeDecodeSet encodeSet) throws IOException, DecompileException {

		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}

		paramDecoder = encodeSet.callbackQuery;
		resultEncoder = encodeSet.callbackResponse;
		int validatedTimeoutMs = getTimeoutMs(timeoutSecs);
		GTimerMonitor timerMonitor = GTimer.scheduleRunnable(validatedTimeoutMs, timeoutRunnable);

		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			writeString(encodeSet.mainQuery);
			write(command_end);
			readResponse(encodeSet.mainResponse);
		}
		catch (IOException e) {
			statusGood = false;
			if (timerMonitor.didRun()) {
				// Timeout occurred
				throw new DecompileException("process", "timeout");
			}
			throw e;
		}
		finally {
			timerMonitor.cancel();
		}
	}

	private int getTimeoutMs(int timeoutSecs) {
		if (timeoutSecs == 0) {
			return -1;
		}
		return timeoutSecs * 1000;
	}

	/**
	 * Send a command with 2 parameters to the decompiler and read the result
	 * @param command string to send
	 * @param param1  is the first parameter string
	 * @param param2  is the second parameter string
	 * @param response the response accumulator
	 * @throws IOException for any problems with the pipe to the decompiler process
	 * @throws DecompileException for problems executing the command
	 */
	public synchronized void sendCommand2Params(String command, String param1, String param2,
			ByteIngest response) throws IOException, DecompileException {
		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}
		paramDecoder = null;	// Don't expect callback queries
		resultEncoder = null;
		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			writeString(param1);
			writeString(param2);
			write(command_end);
			readResponse(response);
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
	}

	/**
	 * Set an upper limit on the amount of data that can be sent back by the decompiler in response
	 * to a single command.
	 * @param maxResultSizeMBytes is the maximum size in megabytes
	 */
	public void setMaxResultSize(int maxResultSizeMBytes) {
		this.maxResultSizeMBYtes = maxResultSizeMBytes;
	}

	/**
	 * Send a command to the decompiler with one parameter and return the result
	 * @param command is the command string
	 * @param param1 is the encoded parameter
	 * @param response is the result accumulator
	 * @throws IOException for problems with the pipe to the decompiler process
	 * @throws DecompileException for problems executing the command
	 */
	public synchronized void sendCommand1Param(String command, Encoder param1, ByteIngest response)
			throws IOException, DecompileException {
		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}
		paramDecoder = null;	// Don't expect callback queries
		resultEncoder = null;
		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			writeString(param1);
			write(command_end);
			readResponse(response);
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
	}

	/**
	 * Send a command to the decompiler with one parameter and return the result
	 * @param command is the command string
	 * @param param1 is the parameter encoded as a string
	 * @param response is the result accumulator
	 * @throws IOException for problems with the pipe to the decompiler process
	 * @throws DecompileException for problems executing the command
	 */
	public synchronized void sendCommand1Param(String command, String param1, ByteIngest response)
			throws IOException, DecompileException {
		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}
		paramDecoder = null;	// Don't expect callback queries
		resultEncoder = null;
		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			writeString(param1);
			write(command_end);
			readResponse(response);
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
	}

	// Calls from the decompiler

	private void getRegister() throws IOException, DecoderException {
		resultEncoder.clear();
		String name = paramDecoder.readString(ATTRIB_NAME);
		callback.getRegister(name, resultEncoder);
		write(query_response_start);
		if (!resultEncoder.isEmpty()) {
			writeString(resultEncoder);
		}
		write(query_response_end);
	}

	private void getRegisterName() throws IOException, DecoderException {
		int el = paramDecoder.openElement(ELEM_ADDR);
		Address addr = AddressXML.decodeFromAttributes(paramDecoder);
		int size = (int) paramDecoder.readSignedInteger(ATTRIB_SIZE);
		paramDecoder.closeElement(el);

		String res = callback.getRegisterName(addr, size);
		write(query_response_start);
		writeString(res);
		write(query_response_end);
	}

	private void getTrackedRegisters() throws IOException, DecoderException {
		resultEncoder.clear();
		Address addr = AddressXML.decode(paramDecoder);
		callback.getTrackedRegisters(addr, resultEncoder);
		write(query_response_start);
		writeString(resultEncoder);
		write(query_response_end);
	}

	private void getUserOpName() throws IOException, DecoderException {
		int index = (int) paramDecoder.readSignedInteger(ATTRIB_INDEX);
		String res = callback.getUserOpName(index);
		if (res == null) {
			res = "";
		}
		write(query_response_start);
		writeString(res);
		write(query_response_end);
	}

	private void getPcode() throws IOException, DecoderException {
		resultEncoder.clear();
		Address addr = AddressXML.decode(paramDecoder);
		callback.getPcode(addr, resultEncoder);
		write(query_response_start);
		if (!resultEncoder.isEmpty()) {
			writeString(resultEncoder);
		}
		write(query_response_end);
	}

	private void getPcodeInject(int type) throws IOException, DecoderException,
			UnknownInstructionException, MemoryAccessException, NotFoundException {
		resultEncoder.clear();
		String name = paramDecoder.readString(ATTRIB_NAME);
		callback.getPcodeInject(name, paramDecoder, type, resultEncoder);
		write(query_response_start);
		if (!resultEncoder.isEmpty()) {
			writeString(resultEncoder);
		}
		write(query_response_end);
	}

	private void getCPoolRef() throws IOException, DecoderException {
		resultEncoder.clear();
		int size = (int) paramDecoder.readSignedInteger(ATTRIB_SIZE);
		long refs[] = new long[size];
		for (int i = 0; i < size; ++i) {
			int el = paramDecoder.openElement(ELEM_VALUE);
			refs[i] = paramDecoder.readUnsignedInteger(ATTRIB_CONTENT);
			paramDecoder.closeElement(el);
		}
		callback.getCPoolRef(refs, resultEncoder);
		write(query_response_start);
		if (!resultEncoder.isEmpty()) {
			writeString(resultEncoder);
		}
		write(query_response_end);
	}

	private void getMappedSymbols() throws IOException, DecoderException {
		resultEncoder.clear();
		Address addr = AddressXML.decode(paramDecoder);
		callback.getMappedSymbols(addr, resultEncoder);

		write(query_response_start);
		if (!resultEncoder.isEmpty()) {
			writeString(resultEncoder);
		}
		write(query_response_end);
	}

	private void getNamespacePath() throws IOException, DecoderException {
		resultEncoder.clear();
		long id = paramDecoder.readUnsignedInteger(ATTRIB_ID);
		callback.getNamespacePath(id, resultEncoder);
		write(query_response_start);
		if (!resultEncoder.isEmpty()) {
			writeString(resultEncoder);
		}
		write(query_response_end);
	}

	private void isNameUsed() throws IOException, DecoderException {
		String name = paramDecoder.readString(ATTRIB_NAME);
		long startId = paramDecoder.readUnsignedInteger(ATTRIB_FIRST);
		long stopId = paramDecoder.readUnsignedInteger(ATTRIB_LAST);
		boolean res = callback.isNameUsed(name, startId, stopId);
		write(query_response_start);
		write(string_start);
		write(res ? 't' : 'f');
		write(string_end);
		write(query_response_end);
	}

	private void getExternalRef() throws IOException, DecoderException {
		resultEncoder.clear();
		Address addr = AddressXML.decode(paramDecoder);
		callback.getExternalRef(addr, resultEncoder);
		write(query_response_start);
		if (!resultEncoder.isEmpty()) {
			writeString(resultEncoder);
		}
		write(query_response_end);
	}

	private void getCodeLabel() throws IOException, DecoderException {
		Address addr = AddressXML.decode(paramDecoder);
		String res = callback.getCodeLabel(addr);
		if (res == null) {
			res = "";
		}
		write(query_response_start);
		writeString(res);
		write(query_response_end);
	}

	private void getComments() throws IOException, DecoderException {
		resultEncoder.clear();
		int types = (int) paramDecoder.readUnsignedInteger(ATTRIB_TYPE);
		Address addr = AddressXML.decode(paramDecoder);

		callback.getComments(addr, types, resultEncoder);
		write(query_response_start);
		writeString(resultEncoder);
		write(query_response_end);
	}

	private void getDataType() throws IOException, DecoderException {
		resultEncoder.clear();
		String name = paramDecoder.readString(ATTRIB_NAME);
		long id = paramDecoder.readSignedInteger(ATTRIB_ID);
		callback.getDataType(name, id, resultEncoder);
		write(query_response_start);
		if (!resultEncoder.isEmpty()) {
			writeString(resultEncoder);
		}
		write(query_response_end);
	}

	private void getBytes() throws IOException, DecoderException {
		int el = paramDecoder.openElement(ELEM_ADDR);
		Address addr = AddressXML.decodeFromAttributes(paramDecoder);
		int size = (int) paramDecoder.readSignedInteger(ATTRIB_SIZE);
		paramDecoder.closeElement(el);
		byte[] res = callback.getBytes(addr, size);
		write(query_response_start);
		if ((res != null) && (res.length > 0)) {
			write(byte_start);
			byte[] dblres = new byte[res.length * 2];
			for (int i = 0; i < res.length; i++) {
				dblres[i * 2] = (byte) (((res[i] >> 4) & 0xf) + 65);
				dblres[i * 2 + 1] = (byte) ((res[i] & 0xf) + 65);
			}
			write(dblres);
			write(byte_end);
		}
		write(query_response_end);
	}

	private void getStringData() throws IOException, DecoderException {
		int maxChars = (int) paramDecoder.readSignedInteger(ATTRIB_MAXSIZE);
		String dtName = paramDecoder.readString(ATTRIB_TYPE);
		long dtId = paramDecoder.readUnsignedInteger(ATTRIB_ID);
		Address addr = AddressXML.decode(paramDecoder);
		DecompileCallback.StringData stringData =
			callback.getStringData(addr, maxChars, dtName, dtId);
		write(query_response_start);
		if (stringData != null) {
			byte[] res = stringData.byteData;
			int sz = res.length + 1;		// We add a null terminator character
			int sz1 = (sz & 0x3f) + 0x20;
			sz >>>= 6;
			int sz2 = (sz & 0x3f) + 0x20;
			write(byte_start);
			write(sz1);
			write(sz2);
			write(stringData.isTruncated ? 1 : 0);
			byte[] dblres = new byte[res.length * 2 + 2];
			for (int i = 0; i < res.length; i++) {
				dblres[i * 2] = (byte) (((res[i] >> 4) & 0xf) + 65);
				dblres[i * 2 + 1] = (byte) ((res[i] & 0xf) + 65);
			}
			dblres[res.length * 2] = 65;		// Adding null terminator
			dblres[res.length * 2 + 1] = 65;
			write(dblres);
			write(byte_end);
		}
		write(query_response_end);
	}

	private void write(byte[] bytes) throws IOException {
		if (nativeOut == null) {
			return;
		}

		nativeOut.write(bytes);
	}

	private void write(int i) throws IOException {
		if (nativeOut == null) {
			return;
		}

		nativeOut.write(i);
	}
}
