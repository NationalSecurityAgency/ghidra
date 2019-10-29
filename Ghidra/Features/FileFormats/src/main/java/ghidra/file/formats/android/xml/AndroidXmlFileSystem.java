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
package ghidra.file.formats.android.xml;

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

/**
 * This is a {@link GFileSystem} that provides a single file, which is the text version
 * of a binary android xml file.
 * <p>
 *
 * NOTE: most of this code was hijacked from AXMLPrinter.java class!
 *
 */
@FileSystemInfo(type = "androidxml", description = "Android XML", factory = GFileSystemBaseFactory.class)
public class AndroidXmlFileSystem extends GFileSystemBase {

	public static boolean isAndroidXmlFile(File f, TaskMonitor monitor) throws IOException {
		try (RandomAccessByteProvider rabp = new RandomAccessByteProvider(f)) {
			return isAndroidXmlFile(rabp, monitor);
		}
	}

	public static boolean isAndroidXmlFile(ByteProvider provider, TaskMonitor monitor)
			throws IOException {
		byte[] actualBytes =
			provider.readBytes(0, AndroidXmlConvertor.ANDROID_BINARY_XML_MAGIC.length);
		if (!Arrays.equals(actualBytes, AndroidXmlConvertor.ANDROID_BINARY_XML_MAGIC)) {
			return false;
		}

		try (InputStream is = new ByteProviderInputStream(provider, 0, provider.length())) {
			StringWriter sw = new StringWriter();
			AndroidXmlConvertor.convert(is, new PrintWriter(sw), monitor);
			return true;
		}
		catch (IOException | CancelledException e) {
			return false;
		}
	}

	private GFileImpl payloadFile;
	private byte[] payloadBytes;

	public AndroidXmlFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	public GFile getPayloadFile() {
		return payloadFile;
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		return isAndroidXmlFile(provider, monitor);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		try (InputStream is = new ByteProviderInputStream(provider, 0, provider.length())) {
			StringWriter sw = new StringWriter();
			AndroidXmlConvertor.convert(is, new PrintWriter(sw), monitor);
			payloadBytes = sw.toString().getBytes();
		}
		catch (IOException e) {
			payloadBytes = "failed to convert".getBytes();
		}
		payloadFile = GFileImpl.fromFilename(this, root, "XML", false, payloadBytes.length, null);
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {
		return new ByteArrayInputStream(payloadBytes);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		List<GFile> tmp = new ArrayList<>();
		tmp.add(payloadFile);
		return tmp;
	}
}
