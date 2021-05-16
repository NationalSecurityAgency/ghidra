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

import java.io.*;

import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PackedBytes;
import ghidra.util.Msg;
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
	private int maxResultSizeMBYtes = 50; // maximum result size in MBytes to allow from decompiler

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
		if (exepath == null) {
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

	private int readToBuffer(LimitedByteBuffer buf) throws IOException {
		int cur;
		for (;;) {
			cur = nativeIn.read();
			while (cur > 0) {
				buf.append((byte) cur);
				cur = nativeIn.read();
			}
			if (cur == -1) {
				break;
			}
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

	private String readQueryString() throws IOException {
		int type = readToBurst();
		if (type != 14) {
			throw new IOException("GHIDRA/decompiler alignment error");
		}
		LimitedByteBuffer buf = new LimitedByteBuffer(16, 1 << 16);
		type = readToBuffer(buf);
		if (type != 15) {
			throw new IOException("GHIDRA/decompiler alignment error");
		}
		return buf.toString();
	}

	private void writeString(String msg) throws IOException {
		write(string_start);
		write(msg.getBytes());
		write(string_end);
	}

	/**
	 * Transfer bytes written to -out- to decompiler process
	 * @param out has the collected byte for this write
	 * @throws IOException for any problems with the output stream
	 */
	private void writeBytes(PackedBytes out) throws IOException {
		write(string_start);
		int sz = out.size();
		int sz1 = (sz & 0x3f) + 0x20;
		sz >>>= 6;
		int sz2 = (sz & 0x3f) + 0x20;
		sz >>>= 6;
		int sz3 = (sz & 0x3f) + 0x20;
		sz >>>= 6;
		int sz4 = (sz & 0x3f) + 0x20;
		write(sz1);
		write(sz2);
		write(sz3);
		write(sz4);
		if (nativeOut != null) { // null if disposed
			out.writeTo(nativeOut);
		}
		write(string_end);
	}

	private void generateException() throws IOException, DecompileException {
		String type = readQueryString();
		String message = readQueryString();
		readToBurst(); // Read exception terminator
		if (type.equals("alignment")) {
			throw new IOException("Alignment error: " + message);
		}
		throw new DecompileException(type, message);
	}

	private LimitedByteBuffer readResponse() throws IOException, DecompileException {
		readToResponse();
		int type = readToBurst();
		String name;
		LimitedByteBuffer retbuf = null;
		LimitedByteBuffer buf = null;

		while (type != 7) {
			switch (type) {
				case 4:
					name = readQueryString();
					try {
						if (name.length() < 4) {
							throw new Exception("Bad decompiler query: " + name);
						}
						switch (name.charAt(3)) {
							case 'a':							// isNameUsed
								isNameUsed();
								break;
							case 'B':
								getBytes();						// getBytes
								break;
							case 'C':
								if (name.equals("getComments")) {
									getComments();
								}
								else if (name.equals("getCallFixup")) {
									getPcodeInject(InjectPayload.CALLFIXUP_TYPE);
								}
								else if (name.equals("getCallotherFixup")) {
									getPcodeInject(InjectPayload.CALLOTHERFIXUP_TYPE);
								}
								else if (name.equals("getCallMech")) {
									getPcodeInject(InjectPayload.CALLMECHANISM_TYPE);
								}
								else {
									getCPoolRef();
								}
								break;
							case 'E':
								getExternalRefXML();			// getExternalRefXML
								break;
							case 'M':
								getMappedSymbolsXML();			// getMappedSymbolsXML
								break;
							case 'N':
								getNamespacePath();
								break;
							case 'P':
								getPcodePacked();				// getPacked
								break;
							case 'R':
								if (name.equals("getRegister")) {
									getRegister();
								}
								else {
									getRegisterName();
								}
								break;
							case 'S':
								if (name.equals("getString")) {
									getStringData();
								}
								else {
									getSymbol();					// getSymbol
								}
								break;
							case 'T':
								if (name.equals("getType")) {
									getType();
								}
								else {
									getTrackedRegisters();
								}
								break;
							case 'U':
								getUserOpName();				// getUserOpName
								break;
							case 'X':
								getPcodeInject(InjectPayload.EXECUTABLEPCODE_TYPE);
								break;
							default:
								throw new Exception("Unsupported decompiler query '" + name + "'");
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
					if (buf != null) {
						throw new IOException("Nested decompiler output");
					}
					// Allocate storage buffer for the result, which is generally not tiny. So we
					// start with any initial allocation of 1024 bytes, also give an absolute upper bound
					// determined by maxResultSizeMBYtes
					buf = new LimitedByteBuffer(1024, maxResultSizeMBYtes << 20);
					break;
				case 15:			// This is the end of the main decompiler output
					if (buf == null) {
						throw new IOException("Mismatched string header");
					}
					retbuf = buf;
					buf = null;		// Reset the main buffer as a native message may follow
					break;
				case 16:			// Beginning of any native message from the decompiler
//				if (buf!=null)
//					throw new IOException("Nested decompiler output");
					// if buf is non-null, then res was interrupted
					// so we just throw out the partial result
					buf = new LimitedByteBuffer(64, 1 << 20);
					break;
				case 17:			// End of the native message from the decompiler
					if (buf == null) {
						throw new IOException("Mismatched message header");
					}
					callback.setNativeMessage(buf.toString());
					buf = null;
					break;
				default:
					throw new IOException("GHIDRA/decompiler alignment error");

			}
			if (buf == null) {
				type = readToBurst();
			}
			else {
				type = readToBuffer(buf);
			}
		}
		return retbuf;
	}

	// Calls to the decompiler

	/**
	 * Initialize decompiler for a particular platform
	 * @param cback = callback object for decompiler
	 * @param pspecxml = string containing .pspec xml
	 * @param cspecxml = string containing .cspec xml
	 * @param tspecxml = XML string containing translator spec
	 * @param coretypesxml = XML description of core data-types
	 * @throws IOException for problems with the pipe to the decompiler process
	 * @throws DecompileException for problems executing the command
	 */
	public synchronized void registerProgram(DecompileCallback cback, String pspecxml,
			String cspecxml, String tspecxml, String coretypesxml)
			throws IOException, DecompileException {
		callback = cback;

		setup();
		String restring = null;
		try {
			write(command_start);
			writeString("registerProgram");
			writeString(pspecxml);
			writeString(cspecxml);
			writeString(tspecxml);
			writeString(coretypesxml);
			write(command_end);
			restring = readResponse().toString();
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
		archId = Integer.parseInt(restring);
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
		String restring = null;
		write(command_start);
		writeString("deregisterProgram");
		writeString(Integer.toString(archId));
		write(command_end);
		restring = readResponse().toString();
		callback = null;
		int res = Integer.parseInt(restring);
		return res;
	}

	/**
	 * Send a single command to the decompiler with no parameters and return response
	 * @param command is the name of the command to execute
	 * @return the response String
	 * @throws IOException for any problems with the pipe to the decompiler process
	 * @throws DecompileException for any problems executing the command
	 */
	public synchronized LimitedByteBuffer sendCommand(String command)
			throws IOException, DecompileException {
		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}
		LimitedByteBuffer resbuf = null;
		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			write(command_end);
			resbuf = readResponse();
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
		return resbuf;
	}

	public synchronized boolean isReady() {
		return statusGood;
	}

	/**
	 * @param command the decompiler should execute
	 * @param param an additional parameter for the command
	 * @param timeoutSecs the number of seconds to run before timing out
	 * @return the response string
	 * @throws IOException for any problems with the pipe to the decompiler process
	 * @throws DecompileException for any problems while executing the command
	 */
	public synchronized LimitedByteBuffer sendCommand1ParamTimeout(String command, String param,
			int timeoutSecs) throws IOException, DecompileException {

		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}

		LimitedByteBuffer resbuf = null;
		int validatedTimeoutMs = getTimeoutMs(timeoutSecs);
		GTimerMonitor timerMonitor = GTimer.scheduleRunnable(validatedTimeoutMs, timeoutRunnable);

		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			writeString(param);
			write(command_end);
			resbuf = readResponse();
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
		return resbuf;
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
	 * @return the result string
	 * @throws IOException for any problems with the pipe to the decompiler process
	 * @throws DecompileException for problems executing the command
	 */
	public synchronized LimitedByteBuffer sendCommand2Params(String command, String param1,
			String param2) throws IOException, DecompileException {
		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}
		LimitedByteBuffer resbuf = null;
		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			writeString(param1);
			writeString(param2);
			write(command_end);
			resbuf = readResponse();
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
		return resbuf;
	}

	public void setMaxResultSize(int maxResultSizeMBytes) {
		this.maxResultSizeMBYtes = maxResultSizeMBytes;
	}

	/**
	 * Send a command to the decompiler with one parameter and return the result
	 * @param command is the command string
	 * @param param1 is the parameter as a string
	 * @return the result string
	 * @throws IOException for problems with the pipe to the decompiler process
	 * @throws DecompileException for problems executing the command
	 */
	public synchronized LimitedByteBuffer sendCommand1Param(String command, String param1)
			throws IOException, DecompileException {
		if (!statusGood) {
			throw new IOException(command + " called on bad process");
		}
		LimitedByteBuffer resbuf = null;
		try {
			write(command_start);
			writeString(command);
			writeString(Integer.toString(archId));
			writeString(param1);
			write(command_end);
			resbuf = readResponse();
		}
		catch (IOException e) {
			statusGood = false;
			throw e;
		}
		return resbuf;
	}

	// Calls from the decompiler

	private void getRegister() throws IOException {
		String name = readQueryString();
		String res = callback.getRegister(name);
		write(query_response_start);
		if ((res != null) && (res.length() != 0)) {
			writeString(res);
		}
		write(query_response_end);
	}

	private void getRegisterName() throws IOException {
		String addr = readQueryString();

		String res = callback.getRegisterName(addr);
		if (res == null) {
			res = "";
		}
		write(query_response_start);
		writeString(res);
		write(query_response_end);
	}

	private void getTrackedRegisters() throws IOException {
		String addr = readQueryString();
		String res = callback.getTrackedRegisters(addr);
		if (res == null) {
			res = "";
		}
		write(query_response_start);
		writeString(res);
		write(query_response_end);
	}

	private void getUserOpName() throws IOException {
		String indexStr = readQueryString();
		String res = callback.getUserOpName(indexStr);
		if (res == null) {
			res = "";
		}
		write(query_response_start);
		writeString(res);
		write(query_response_end);
	}

	private void getPcodePacked() throws IOException {
		String addr = readQueryString();
		PackedBytes out = callback.getPcodePacked(addr);
		write(query_response_start);
		if ((out != null) && (out.size() != 0)) {
			writeBytes(out);
		}
		write(query_response_end);
	}

	private void getPcodeInject(int type) throws IOException {
		String name = readQueryString();
		String context = readQueryString();
		String res = callback.getPcodeInject(name, context, type);
		write(query_response_start);
		if ((res != null) && (res.length() != 0)) {
			writeString(res);
		}
		write(query_response_end);
	}

	private void getCPoolRef() throws IOException {
		String liststring = readQueryString();
		String[] split = liststring.split(",");
		long[] refs = new long[split.length];
		for (int i = 0; i < split.length; ++i) {
			refs[i] = Long.parseUnsignedLong(split[i], 16);
		}
		String res = callback.getCPoolRef(refs);
		write(query_response_start);
		if ((res != null) && (res.length() != 0)) {
			writeString(res);
		}
		write(query_response_end);
	}

	private void getMappedSymbolsXML() throws IOException {
		String addr = readQueryString();

		String res = callback.getMappedSymbolsXML(addr);
		write(query_response_start);
		if ((res != null) && (res.length() != 0)) {
			writeString(res);
		}
		write(query_response_end);
	}

	private void getNamespacePath() throws IOException {
		String idString = readQueryString();
		long id = Long.parseLong(idString, 16);
		String res = callback.getNamespacePath(id);
		write(query_response_start);
		if ((res != null) && (res.length() != 0)) {
			writeString(res);
		}
		write(query_response_end);
	}

	private void isNameUsed() throws IOException {
		String name = readQueryString();
		String startString = readQueryString();
		String stopString = readQueryString();
		long startId = Long.parseLong(startString, 16);
		long stopId = Long.parseLong(stopString, 16);
		boolean res = callback.isNameUsed(name, startId, stopId);
		write(query_response_start);
		write(string_start);
		write(res ? 't' : 'f');
		write(string_end);
		write(query_response_end);
	}

	private void getExternalRefXML() throws IOException {
		String refaddr = readQueryString();
		String res = callback.getExternalRefXML(refaddr);
		write(query_response_start);
		if ((res != null) && (res.length() != 0)) {
			writeString(res);
		}
		write(query_response_end);
	}

	private void getSymbol() throws IOException {
		String addr = readQueryString();

		String res = callback.getSymbol(addr);
		if (res == null) {
			res = "";
		}
		write(query_response_start);
		writeString(res);
		write(query_response_end);
	}

	private void getComments() throws IOException {
		String addr = readQueryString();
		String flags = readQueryString();
		String res = callback.getComments(addr, flags);
		if (res == null) {
			res = "";
		}
		write(query_response_start);
		writeString(res);
		write(query_response_end);
	}

//	private void getScope() throws IOException {
//		String namepath = readQueryString();
//		String res = callback.getScope(namepath);
//		if (res==null)
//			res = "";
//		write(query_response_start);
//		writeString(res);
//		write(query_response_end);
//	}

	private void getType() throws IOException {
		String name = readQueryString();
		String id = readQueryString();
		String res = callback.getType(name, id);
		write(query_response_start);
		if ((res != null) && (res.length() != 0)) {
			writeString(res);
		}
		write(query_response_end);
	}

	private void getBytes() throws IOException {
		String size = readQueryString();
		byte[] res = callback.getBytes(size);
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

	private void getStringData() throws IOException {
		String addr = readQueryString();
		String dtName = readQueryString();
		String dtId = readQueryString();
		DecompileCallback.StringData stringData = callback.getStringData(addr, dtName, dtId);
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
