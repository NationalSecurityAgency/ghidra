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
package ghidra.file.crypto;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

/**
 * NOTE:  ALL DECRYPTOR CLASSES MUST END IN "Decryptor".  If not,
 * the ClassSearcher will not find them.
 */
public interface Decryptor extends ExtensionPoint {

	/**
	 * Returns TRUE if this decryptor implementation
	 * can in fact decrypt the bytes contained in the byte provider.
	 * @param provider the byte provider.
	 * @return TRUE if this decryptor can decrypt 
	 * @throws IOException if an I/O occurs
	 */
	boolean isValid(ByteProvider provider) throws IOException;

	/**
	 * Actually decrypt the bytes in the byte provider.
	 * @param firmwareName
	 * @param firmwarePath
	 * @param provider
	 * @param monitor
	 * @return
	 * @throws IOException
	 * @throws CryptoException
	 * @throws CancelledException
	 */
	DecryptedPacket decrypt(String firmwareName, String firmwarePath, ByteProvider provider, TaskMonitor monitor) 
					throws IOException, CryptoException, CancelledException;
}
