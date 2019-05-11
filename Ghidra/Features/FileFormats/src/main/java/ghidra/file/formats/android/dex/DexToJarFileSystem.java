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
package ghidra.file.formats.android.dex;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.io.FilenameUtils;
import org.objectweb.asm.*;

import com.googlecode.d2j.dex.ClassVisitorFactory;
import com.googlecode.d2j.dex.ExDex2Asm;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.reader.DexFileReader;
import com.googlecode.d2j.visitors.DexFileVisitor;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.android.dex.format.DexConstants;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;
import utilities.util.FileUtilities;

/**
 * {@link GFileSystem} that converts a DEX file into a JAR file.
 */
@FileSystemInfo(type = "dex2jar", description = "Android DEX to JAR", factory = GFileSystemBaseFactory.class)
public class DexToJarFileSystem extends GFileSystemBase {

	private GFileImpl jarFile;

	public DexToJarFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	public GFile getJarFile() {
		return jarFile;
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {

		if (file.equals(jarFile)) {
			FileCacheEntry jarFileInfo = getJarFile(monitor);
			return new FileInputStream(jarFileInfo.file);
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return (directory == null || directory.equals(root)) ? Arrays.asList(jarFile)
				: Collections.emptyList();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		return DexConstants.isDexFile(provider);
	}

	private FileCacheEntry getJarFile(TaskMonitor monitor) throws CancelledException, IOException {
		TaskMonitor upwtm = new UnknownProgressWrappingTaskMonitor(monitor, 1);
		upwtm.setMessage("Converting DEX to JAR...");

		FSRLRoot targetFSRL = getFSRL();
		FSRL containerFSRL = targetFSRL.getContainer();
		File containerFile = fsService.getFile(containerFSRL, monitor);

		FileCacheEntry derivedFileInfo =
			fsService.getDerivedFilePush(containerFSRL, "dex2jar", (os) -> {
				try (ZipOutputStream outputStream = new ZipOutputStream(os)) {

					DexToJarExceptionHandler exceptionHandler = new DexToJarExceptionHandler();

					DexFileReader reader =
						new DexFileReader(FileUtilities.getBytesFromFile(containerFile));

					DexFileNode fileNode = new DexFileNode();
					try {
						reader.accept(fileNode, DexFileReader.IGNORE_READ_EXCEPTION);
					}
					catch (Exception ex) {
						exceptionHandler.handleFileException(ex);
					}

					DexFileVisitor visitor = new DexFileVisitor();
					reader.accept(visitor);

					ClassVisitorFactory classVisitorFactory = name -> new ClassVisitor(Opcodes.ASM4,
						new ClassWriter(ClassWriter.COMPUTE_MAXS)) {
						//NOTE: EXTRACTED FROM Dex2jar.java
						@Override
						public void visitEnd() {
							super.visitEnd();
							ClassWriter cw = (ClassWriter) super.cv;

							byte[] data;
							try {
								// FIXME handle 'java.lang.RuntimeException: Method code too large!'
								data = cw.toByteArray();
							}
							catch (Exception ex) {
								//System.err.println(String.format("ASM fail to generate .class file: %s", name));
								Msg.warn(this,
									String.format("ASM fail to generate .class file: %s", name));
								exceptionHandler.handleFileException(ex);
								return;
							}
							try {
								ZipEntry entry = new ZipEntry(name + ".class");
								outputStream.putNextEntry(entry);
								outputStream.write(data);
								outputStream.closeEntry();
								upwtm.incrementProgress(1);

							}
							catch (IOException e) {
								//e.printStackTrace(System.err);
								Msg.warn(this, e);
							}
						}
					};

					ExDex2Asm exDex2Asm = new ExDex2Asm(exceptionHandler);
					exDex2Asm.convertDex(fileNode, classVisitorFactory);

					if (exceptionHandler.getFileException() != null) {
						throw new IOException(exceptionHandler.getFileException());
					}

					outputStream.finish();
				}

			}, monitor);

		return derivedFileInfo;
	}

	@Override
	public void open(TaskMonitor monitor) throws CancelledException, IOException {

		FileCacheEntry jarFileInfo = getJarFile(monitor);

		FSRLRoot targetFSRL = getFSRL();
		FSRL containerFSRL = targetFSRL.getContainer();
		String baseName = FilenameUtils.removeExtension(containerFSRL.getName());
		String jarName = baseName + ".jar";
		FSRL jarFSRL = targetFSRL.withPathMD5(jarName, jarFileInfo.md5);
		this.jarFile = GFileImpl.fromFilename(this, root, baseName + ".jar", false,
			jarFileInfo.file.length(), jarFSRL);
	}

	@Override
	public void close() throws IOException {
		super.close();
	}
}
