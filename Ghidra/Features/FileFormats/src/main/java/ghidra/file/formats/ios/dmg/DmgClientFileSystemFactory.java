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
package ghidra.file.formats.ios.dmg;

import java.io.File;
import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.xar.XARUtil;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;
import utilities.util.ArrayUtilities;

/**
 * Handles probing for and creating {@link DmgClientFileSystem} instances.
 * <p>
 */
public class DmgClientFileSystemFactory implements
		GFileSystemFactoryByteProvider<DmgClientFileSystem>, GFileSystemProbeByteProvider {

	public DmgClientFileSystemFactory() {
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor taskMonitor) throws IOException, CancelledException {

		if (!isDmgPresent()) {
			return false;
		}

		//sometimes a PKG (or XAR) can resemble a DMG
		if (XARUtil.isXAR(byteProvider)) {
			return false;
		}

		return hasUDIF(byteProvider) || isEncrypted(byteProvider);
	}

	private static boolean isEncrypted(byte[] startBytes) {
		return ArrayUtilities.arrayRangesEquals(startBytes, 0, DmgConstants.DMG_MAGIC_BYTES_v1, 0,
			DmgConstants.DMG_MAGIC_BYTES_v1.length) ||
			ArrayUtilities.arrayRangesEquals(startBytes, 0, DmgConstants.DMG_MAGIC_BYTES_v2, 0,
				DmgConstants.DMG_MAGIC_BYTES_v2.length);
	}

	private static boolean isEncrypted(ByteProvider bp) {
		try {
			byte[] startBytes = bp.readBytes(0, DmgConstants.DMG_MAGIC_LENGTH);
			return isEncrypted(startBytes);
		}
		catch (IOException ioe) {
			// ignore, fall thru to return false
		}
		return false;
	}

	private static boolean hasUDIF(ByteProvider bp) {
		try {
			UDIFHeader udif = UDIFHeader.read(bp);
			return udif.isValid() && udif.hasGoodOffsets(bp);
		}
		catch (IOException e) {
			// ignore, fall thru
		}
		return false;
	}

	@Override
	public DmgClientFileSystem create(FSRLRoot targetFSRL, ByteProvider provider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		FSRL containerFSRL = provider.getFSRL();
		String dmgName = containerFSRL.getName();

		ByteProvider decryptedProvider;
		if (isEncrypted(provider)) {
			if (containerFSRL.getNestingDepth() < 2) {
				throw new CryptoException("Unable to decrypt DMG data because DMG crypto keys " +
					"are specific to the container it is embedded in and this DMG was not " +
					"in a container");
			}

			// get the name of the iphone.ipsw container so we can lookup our crypto keys
			// based on that.
			String containerName = containerFSRL.getName(1);

			decryptedProvider = fsService.getDerivedByteProvider(containerFSRL, null,
				"decrypted " + containerName, provider.length(),
				() -> new DmgDecryptorStream(containerName, dmgName, provider), monitor);
		}
		else {
			decryptedProvider = provider;
		}

		File decryptedDmgFile = File.createTempFile("ghidra_decrypted_dmg_file",
			Long.toString(System.currentTimeMillis()));
		monitor.setMessage("Copying DMG container to temp file");
		monitor.initialize(decryptedProvider.length());
		FSUtilities.copyByteProviderToFile(decryptedProvider, decryptedDmgFile, monitor);

		DmgClientFileSystem fs =
			new DmgClientFileSystem(decryptedDmgFile, true, targetFSRL, fsService);
		try {
			fs.mount(monitor);
			return fs;
		}
		catch (IOException ioe) {
			Msg.error(this, "Failed to mount DMG file system " + containerFSRL + ": ", ioe);
			fs.close();
			throw ioe;
		}
	}

	/**
	 * A cached check for the presence of the DMG module.
	 * 
	 * @return true if the DMG module, is present; otherwise, false.
	 */
	private static boolean isDmgPresent() {
		return DmgPresentHolder.DMG_PRESENT;
	}

	private static class DmgPresentHolder {
		static final boolean DMG_PRESENT = isDmgPresent();

		private static boolean isDmgPresent() {
			ResourceFile dmgModule =
				Application.getModuleRootDir(DmgServerProcessManager.DMG_MODULE_NAME);
			if (dmgModule == null) {
				Msg.debug(DmgClientFileSystemFactory.class,
					"The required \"" + DmgServerProcessManager.DMG_MODULE_NAME + "\"" +
						" module is not installed.   You must install this module in order to " +
						"open DMG filesystems.");
				return false;
			}
			return true;
		}
	}

}
