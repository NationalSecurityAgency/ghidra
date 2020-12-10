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
package ghidra.dbg.sctl.protocol.consts;

import ghidra.comm.util.BitmaskUniverse;
import ghidra.dbg.sctl.client.SctlExtension;

/**
 * Taken from Evkind in the SCTL documentation
 * 
 * Two extra bits have been added to make the protocol more orthogonal, but remain backward
 * compatible. The {@link #Estopped} bit indicates that the target has been stopped as part of this
 * trace event. This is the usual case except for {@link #Efork} and {@link #Eclone} on Windows. The
 * {@link #Erunning} bit indicates the opposite: the target is still running, despite issuing this
 * trace event. Servers supporting this mechanism must set exactly one of these bits. If neither is
 * present, the client must assume the server does not support the extension, and use the dialect
 * default. To set both is an error.
 * 
 * For now, this modification has been rolled into the SCTL-Bus extension. However, a server cannot
 * use this extension with a non-bus client.
 */
public enum Evkind implements BitmaskUniverse {
	Eclear(0 << 0),
	Eset(1 << 0),
	Esyscall(1 << 1), // Not valid on Windows
	Eexec(1 << 2), // Not valid on Windows
	Efork(1 << 3),
	Eclone(1 << 4),
	Esignal(1 << 5),
	Eexit(1 << 6),
	Etrap(1 << 7),
	Esnap(1 << 8),
	Estepctx(1 << 9),
	Eload(1 << 10),
	Eunload(1 << 11),
	@SctlExtension("The target has stopped")
	Estopped(1 << 12),
	@SctlExtension("The target is still running")
	Erunning(1 << 13);

	public final long mask;

	private Evkind(long mask) {
		this.mask = mask;
	}

	@Override
	public long getMask() {
		return mask;
	}
}
