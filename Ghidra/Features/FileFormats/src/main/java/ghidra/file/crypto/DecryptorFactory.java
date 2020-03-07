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

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

/**
 * Not used by any known code, not tested.
 */
@Deprecated
public final class DecryptorFactory {

	public final static DecryptedPacket decrypt(String firmwareName, String firmwarePath,
			ByteProvider provider, TaskMonitor monitor) throws IOException, CryptoException,
	CancelledException {

		List<Decryptor> instances = ClassSearcher.getInstances(Decryptor.class);
		for (Decryptor decryptor : instances) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			if (decryptor.isValid(provider)) {
				return decryptor.decrypt(firmwareName, firmwarePath, provider, monitor);
			}
		}
		throw new CryptoException("Unable to decrypt " + provider.getName() +
				" unable to locate decryption provider.");
	}
}
