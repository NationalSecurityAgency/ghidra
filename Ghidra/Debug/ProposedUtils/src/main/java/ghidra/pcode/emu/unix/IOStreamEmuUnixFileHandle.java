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
package ghidra.pcode.emu.unix;

import java.io.*;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.sys.EmuIOException;
import ghidra.program.model.lang.CompilerSpec;

/**
 * A simulated file descriptor that proxies a host resource, typically a console/terminal
 */
public class IOStreamEmuUnixFileHandle extends AbstractStreamEmuUnixFileHandle<byte[]> {

	/**
	 * Construct a proxy for the host's standard input
	 * 
	 * @param machine the machine emulating the hardware
	 * @param cSpec the ABI of the target platform
	 * @return the proxy's handle
	 */
	public static IOStreamEmuUnixFileHandle stdin(PcodeMachine<byte[]> machine,
			CompilerSpec cSpec) {
		return new IOStreamEmuUnixFileHandle(machine, cSpec, System.in, null);
	}

	/**
	 * Construct a proxy for the host's standard output
	 * 
	 * @param machine the machine emulating the hardware
	 * @param cSpec the ABI of the target platform
	 * @return the proxy's handle
	 */
	public static IOStreamEmuUnixFileHandle stdout(PcodeMachine<byte[]> machine,
			CompilerSpec cSpec) {
		return new IOStreamEmuUnixFileHandle(machine, cSpec, null, System.out);
	}

	/**
	 * Construct a proxy for the host's standard error output
	 * 
	 * @param machine the machine emulating the hardware
	 * @param cSpec the ABI of the target platform
	 * @return the proxy's handle
	 */
	public static IOStreamEmuUnixFileHandle stderr(PcodeMachine<byte[]> machine,
			CompilerSpec cSpec) {
		return new IOStreamEmuUnixFileHandle(machine, cSpec, null, System.err);
	}

	protected final InputStream input;
	protected final OutputStream output;

	/**
	 * Construct a proxy for a host resource
	 * 
	 * <p>
	 * <b>WARNING:</b> Think carefully before proxying any host resource to a temperamental target
	 * program.
	 * 
	 * @param machine the machine emulating the hardware
	 * @param cSpec the ABI of the target platform
	 * @param input the stream representing the input side of the descriptor, if applicable
	 * @param output the stream representing the output side of the descriptor, if applicable
	 * @return the proxy's handle
	 */
	public IOStreamEmuUnixFileHandle(PcodeMachine<byte[]> machine, CompilerSpec cSpec,
			InputStream input, OutputStream output) {
		super(machine, cSpec);
		this.input = input;
		this.output = output;
	}

	@Override
	public byte[] read(byte[] buf) throws EmuIOException {
		if (input == null) {
			return arithmetic.fromConst(0, offsetBytes);
		}
		try {
			int result = input.read(buf);
			return arithmetic.fromConst(result, offsetBytes);
		}
		catch (IOException e) {
			throw new EmuIOException("Could not read host input stream", e);
		}
	}

	@Override
	public byte[] write(byte[] buf) throws EmuIOException {
		if (output == null) {
			return arithmetic.fromConst(0, offsetBytes);
		}
		try {
			output.write(buf);
			return arithmetic.fromConst(buf.length, offsetBytes);
		}
		catch (IOException e) {
			throw new EmuIOException("Could not write host output stream", e);
		}
	}

	@Override
	public void close() {
		// TODO: Is it my responsibility to close the streams?
	}
}
