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
package ghidra.file.formats.ios.img4;

import java.io.IOException;
import java.util.*;

import javax.swing.Icon;

import org.bouncycastle.asn1.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.file.crypto.CryptoKey;
import ghidra.file.crypto.CryptoKeyFactory;
import ghidra.file.formats.ios.generic.iOS_AesCrypto;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "img4", description = "iOS Img4", factory = GFileSystemBaseFactory.class)
public class Img4FileSystem extends GFileSystemBase {

	private List<GFile> dataFileList = new ArrayList<>();
	private byte[] decryptedBytes = new byte[0];

	public Img4FileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		try {
			byte[] magicBytes = provider.readBytes(0x0, 0x20);
			String magicString = new String(magicBytes);
			return magicString.indexOf("IM4P") != -1;
		}
		catch (Exception e) {
			//ignore...
		}
		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException {
		monitor.setMessage("Opening IMG4...");
		try {
			ASN1InputStream asn1InputStream = new ASN1InputStream(provider.getInputStream(0));
			try {
				ASN1Primitive asn1Primitive = asn1InputStream.readObject();
				if (asn1Primitive instanceof ASN1Sequence) {
					ASN1Sequence asn1Sequence = (ASN1Sequence) asn1Primitive;
					Enumeration<?> enumeration = asn1Sequence.getObjects();
					while (enumeration.hasMoreElements()) {
						if (monitor.isCancelled()) {
							break;
						}
						Object nextElement = enumeration.nextElement();
						if (nextElement instanceof DEROctetString) {
							DEROctetString octet = (DEROctetString) nextElement;

							byte[] encryptedBytes = octet.getOctets();

							FSRLRoot fsFSRL = getFSRL();

							CryptoKey cryptoKey = CryptoKey.NOT_ENCRYPTED_KEY;
							try {
								cryptoKey = CryptoKeyFactory.getCryptoKey(fsFSRL.getName(2),
									fileSystemName);
							}
							catch (IOException e) {
								monitor.setMessage(
									"WARNING: Crypto Key file not found! Trying unencrypted");
							}

							if (cryptoKey == CryptoKey.NOT_ENCRYPTED_KEY) {
								decryptedBytes = encryptedBytes;
							}
							else {
								iOS_AesCrypto aes = new iOS_AesCrypto(cryptoKey.key, cryptoKey.iv);
								decryptedBytes = aes.decrypt(encryptedBytes);
							}

							String filename = "im4p_data";
							GFileImpl dataFile = GFileImpl.fromPathString(this, root, filename,
								null, false, decryptedBytes.length);
							dataFileList.add(dataFile);

							break;
						}
					}
				}
			}
			finally {
				asn1InputStream.close();
			}
		}
		catch (Exception e) {
			throw new IOException("Error opening IMG4 file: ", e);
		}
	}

	@Override
	public void close() throws IOException {
		super.close();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (dataFileList.contains(file)) {
			return new ByteArrayProvider(decryptedBytes, file.getFSRL());
		}
		throw new IOException("Unable to get DATA for " + file.getPath());
	}

	public Icon getIcon() {
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) {
		if (directory == null || directory.equals(root)) {
			return dataFileList;
		}
		return new ArrayList<>();
	}

	public boolean isDirectory(GFileImpl directory) {
		return directory.equals(root);
	}

	public boolean isFile(GFileImpl file) {
		return !file.equals(root);
	}

}
