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
package ghidra.file.formats.cart;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.text.StringEscapeUtils;

import com.google.gson.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.crypto.CryptoSession;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.framework.generic.auth.Password;
import ghidra.util.HashUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@FileSystemInfo(
	type = "cart",
	description = "Compressed and ARC4 Transport (CaRT) neutering format.",
	factory = CartFileSystemFactory.class
)
//@formatter:on
/**
 * File system for the CaRT format (Version 1). Includes creating objects for
 * relevant parsing and retrieving providers for access to decrypted and
 * decompressed data contents.
 *
 * This class does not contain a version identifier because it should be the
 * wrapper to load all versions of CaRT formated files. If/when new versions are
 * released new probe checks should be added and use the appropriate
 * (version-specific?) factories.
 */
public class CartFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);
	private final FileSystemService fsService;

	private ByteProvider byteProvider;
	private ByteProvider payloadProvider;
	private SingleFileSystemIndexHelper fsIndexHelper;
	private CartV1File cartFile;

	/**
	 * CaRT file system constructor.
	 *
	 * @param fsFSRL   The root {@link FSRL} of the file system.
	 * @param fsService The file system service provided by Ghidra instance
	 */
	public CartFileSystem(FSRLRoot fsFSRL, FileSystemService fsService) {
		this.fsFSRL = fsFSRL;
		this.fsService = fsService;
	}

	/**
	 * Opens the specified CaRT container file and initializes this file system with the
	 * contents.
	 *
	 * @param bProvider container file
	 * @param monitor {@link TaskMonitor} to allow the user to monitor and cancel
	 * @throws CancelledException if user cancels
	 * @throws IOException if error when reading data
	 */
	public void mount(ByteProvider bProvider, TaskMonitor monitor)
			throws CancelledException, IOException {
		byteProvider = bProvider;

		try {
			try {
				cartFile = new CartV1File(byteProvider);
			}
			catch (CartInvalidARC4KeyException e) {
				// Could not auto detect key. Prompt user until we have a valid key or they cancel
				try (CryptoSession cryptoSession = fsService.newCryptoSession()) {

					String prompt = this.fsFSRL.getContainer().getName() + " (plaintext or base64)";

					// Iterate through GUI password request attempts until we succeed. hasNext
					// will return true until the user cancels. The prompt will also tell them
					// how many attempts they have made so it is clearer that they are not
					// being successful.
					// Log an error when the password is bad, but perhaps we should make them
					// acknowledge before attempting again?
					for (Iterator<Password> pwIt =
						cryptoSession.getPasswordsFor(this.fsFSRL.getContainer(), prompt); pwIt
								.hasNext();) {

						try (Password passwordValue = pwIt.next()) {
							monitor.setMessage("Testing key...");

							String password = String.valueOf(passwordValue.getPasswordChars());
							cartFile = new CartV1File(byteProvider, password);
							break;
						}
						catch (CartInvalidARC4KeyException arc4E) {
							if (!CartCancelDialogs.promptErrorContinue("Bad Key",
								"Error when testing key for " +
									this.fsFSRL.getContainer().getName() + ":\n" +
									(arc4E.getMessage() != null ? arc4E.getMessage() : "Unknown") +
									"\n Try another key?")) {
								break;
							}
						}

					}
				}
			}
		}
		catch (CartInvalidARC4KeyException e) {
			throw new IOException("Invalid CaRT ARC4 Key: " + e.getMessage());
		}
		catch (CartInvalidCartException e) {
			throw new IOException("Invalid CaRT file: " + e.getMessage());
		}
		catch (CartConfigurationException e) {
			throw new IOException("Invalid CaRT configuration file: " + e.getMessage());
		}

		// If the CaRT File wasn't set, then we don't have a key, throw an error
		if (cartFile == null) {
			throw new IOException("ARC4 key not found or user cancelled.");
		}

		// If/when future CaRT file versions exist, catch the appropriate error and
		// handle them here.
		payloadProvider = getPayload(null, monitor);

		/**
		 * If an MD5 value is provided here it will be carried through the rest of the
		 * system. If null is used instead then the MD5 will be calculated from the
		 * bytes of the file.
		 */
		this.fsIndexHelper = new SingleFileSystemIndexHelper(this, fsFSRL, cartFile.getPath(),
			cartFile.getDataSize(), null // Intentionally using null instead of actual MD5
		);
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (fsIndexHelper != null) {
			fsIndexHelper.clear();
		}
		if (byteProvider != null) {
			byteProvider.close();
			byteProvider = null;
		}
		if (payloadProvider != null) {
			payloadProvider.close();
			payloadProvider = null;
		}
	}

	@Override
	public boolean isClosed() {
		return (fsIndexHelper == null) || fsIndexHelper.isClosed();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndexHelper.lookup(path);
	}

	/**
	 * Helper function to create byte provider for CaRT payload content that is
	 * decompressed and decrypted.
	 *
	 * @param payloadFSRL The payload {@link FSRL} of the file system.
	 * @param monitor The task monitor for this system handling
	 * @return A {@link ByteProvider} for the payload content
	 * @throws CancelledException If the user cancels via the monitor
	 * @throws IOException If the file fails to read or CaRT fails
	 */
	private ByteProvider getPayload(FSRL payloadFSRL, TaskMonitor monitor)
			throws CancelledException, IOException {

		return fsService.getDerivedByteProviderPush(byteProvider.getFSRL(), payloadFSRL, "cart", -1,
			os -> {
				CartV1PayloadExtractor extractor =
					new CartV1PayloadExtractor(byteProvider, os, cartFile);
				extractor.extract(monitor);
			}, monitor);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (fsIndexHelper.isPayloadFile(file)) {
			return new ByteProviderWrapper(payloadProvider, file.getFSRL());
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndexHelper.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();

		// If the specified file isn't the payload file or the cartFile object isn't defined, bail
		if (!fsIndexHelper.isPayloadFile(file) || cartFile == null) {
			return result;
		}

		// Set of keys (lower-case) that are handled manually and should be skipped when
		// adding remaining keys to the file attributes.
		Set<String> skipKeys = new HashSet<>(Set.of("name"));

		// Set to track all attributes that have been added. Used during bulk addition
		// to add with _# suffixes.
		Set<String> addedAttributes = new HashSet<>();

		if (cartFile.getDataSize() >= 0) {
			result.add(FileAttributeType.SIZE_ATTR, cartFile.getDataSize());
		}
		skipKeys.add("length");

		result.add(FileAttributeType.COMPRESSED_SIZE_ATTR, cartFile.getPackedSize());
		result.add(FileAttributeType.IS_ENCRYPTED_ATTR, true);

		// Won't create the CaRT file object if we don't have a valid key
		result.add(FileAttributeType.HAS_GOOD_PASSWORD_ATTR, true);

		// Keep warning as the first custom attribute to display it first
		// in that section of the file information
		result.add("WARNING", """
				CaRT format is often used to neuter and share malicious files.
				Please use caution if exporting original binary.""");

		// Display the ARC4 key, in hex, that is being used
		result.add("ARC4 Key",
			new String(HashUtilities.hexDump(cartFile.getDecryptor().getARC4Key())));

		// Display the stored hashes next
		for (String hashName : CartV1Constants.EXPECTED_HASHES.keySet()) {
			byte[] footerHashValue = cartFile.getFooterHash(hashName);
			skipKeys.add(hashName.toLowerCase());

			if (footerHashValue != null) {
				result.add("Reported " + hashName,
					new String(HashUtilities.hexDump(footerHashValue)));
			}
			else {
				result.add("Reported " + hashName, "Missing");
			}
		}

		// Generate set of keys to protect that we don't want the metadata to be able
		// to overwrite.
		// Warn the user if any of these exist because they may indicate an attempt to
		// mess with the shown information.
		// Also, set up the list of added attributes so far so that we can track and
		// add _# for non-protected.
		Set<String> protectedKeys = new HashSet<>();
		for (FileAttribute<?> attribute : result.getAttributes()) {
			protectedKeys.add(attribute.getAttributeDisplayName().toLowerCase());
			addedAttributes.add(attribute.getAttributeDisplayName());
		}

		// Before processing final metadata for inclusion in file attributes check if
		// CaRT's header/footer merging is obscuring any attempted overwrite of
		// header data with footer data
		Set<String> warnKeys = new HashSet<>();
		for (Entry<String, JsonElement> entry : cartFile.getHeader()
				.optionalHeaderData()
				.entrySet()) {
			if (CartV1Constants.FOOTER_ONLY_KEYS.contains(entry.getKey().toLowerCase())) {
				warnKeys.add(entry.getKey());
			}
		}

		if (!warnKeys.isEmpty()) {
			result.add("SECURITY WARNING",
				"CaRT file metadata may be attempting to overwrite protected file data: " +
					StringEscapeUtils.escapeHtml4(String.join(", ", warnKeys)) + ".");
		}

		// Construct object to pretty print JSON elements to be shown in the display
		Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();

		// Clear any key warnings to prepare to collect a new set
		warnKeys.clear();

		// Walk all the optional header JsonElements, then the optional footer
		// JsonElements adding each to the file's attributes. Skip any that are
		// in the list of keys handled manually.
		for (Entry<String, JsonElement> entry : cartFile.getMetadata().entrySet()) {
			if (skipKeys.contains(entry.getKey().toLowerCase())) {
				continue;
			}

			// Key not being skipped, check if it is protected, if so record then skip
			if (protectedKeys.contains(entry.getKey().toLowerCase())) {
				warnKeys.add(entry.getKey());
				continue;
			}

			String value = "<Unknown>";

			try {
				value = gson.toJson(entry.getValue());
			}
			catch (IllegalStateException e) {
				value = "Invalid JSON String";
			}

			String key = entry.getKey();
			int suffix_counter = 0;

			while (addedAttributes.contains(key)) {
				suffix_counter++;
				// If more than 100 of the same key are found, stop trying to add them
				if (suffix_counter > 100) {
					suffix_counter = -1;
					break;
				}

				key = entry.getKey() + "_" + suffix_counter;
			}

			if (suffix_counter != -1) {
				result.add(key, value);
				addedAttributes.add(key);
			}
		}

		// If any protected keys were skipped, notify the user
		if (!warnKeys.isEmpty()) {
			result.add("SECURITY WARNING",
				"CaRT file metadata may be attempting to overwrite protected file data: " +
					StringEscapeUtils.escapeHtml4(String.join(", ", warnKeys)) +
					". Skipped those keys.");
		}

		return result;
	}
}
