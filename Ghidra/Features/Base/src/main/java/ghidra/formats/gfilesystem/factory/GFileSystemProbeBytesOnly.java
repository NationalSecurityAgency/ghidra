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
package ghidra.formats.gfilesystem.factory;

import ghidra.formats.gfilesystem.FSRL;

/**
 * A {@link GFileSystemProbe} interface for filesystems that can be detected using
 * just a few bytes from the beginning of the containing file.
 * <p>
 * Filesystem probes of this type are given precedence when possible since they
 * tend to be simpler and quicker.
 */
public interface GFileSystemProbeBytesOnly extends GFileSystemProbe {
	/**
	 * Maximum that any GFileSystemProbeBytesOnly is allowed to specify as its
	 * {@link GFileSystemProbeBytesOnly#getBytesRequired()}.
	 */
	public static final int MAX_BYTESREQUIRED = 64 * 1024;

	/**
	 * The minimum number of bytes needed to be supplied to the
	 * {@link #probeStartBytes(FSRL, byte[])} method.
	 * <p>
	 * @return min number of bytes needed for probe
	 */
	public int getBytesRequired();

	/**
	 * Probes the supplied {@code startBytes} byte[] array to determine if this filesystem
	 * implementation can handle the file.
	 *
	 * @param containerFSRL the {@link FSRL} of the file containing the bytes being probed.
	 * @param startBytes a byte array, with a length of at least {@link #getBytesRequired()}
	 * containing bytes from the beginning (ie. offset 0) of the probed file.
	 * @return {@code true} if the specified file is handled by this filesystem implementation,
	 * {@code false} if not.
	 */
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes);
}
