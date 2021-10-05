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
package ghidra.file.formats.java;

import java.io.*;
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.jad.JadProcessController;
import ghidra.file.jad.JadProcessWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Filesystem that decompiles a java .class file (using external JAD decompiler) into
 * a java classname.java source text file and presents the source text file as its
 * only file in the filesystem.
 */
@FileSystemInfo(type = "javaclass", description = "Java Class Decompiler", factory = JavaClassDecompilerFileSystemFactory.class, priority = FileSystemInfo.PRIORITY_LOW)
public class JavaClassDecompilerFileSystem implements GFileSystem {

	private FSRLRoot fsFSRL;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private SingleFileSystemIndexHelper fsIndexHelper;
	private ByteProvider provider;
	private FSRL containerFSRL;
	private String className;
	private String javaSrcFilename;
	private FileSystemService fsService;

	public JavaClassDecompilerFileSystem(FSRLRoot fsFSRL, ByteProvider provider,
			FileSystemService fsService, TaskMonitor monitor)
			throws CancelledException, IOException {
		this.fsService = fsService;
		this.fsFSRL = fsFSRL;
		this.provider = provider;

		this.containerFSRL = provider.getFSRL();
		this.className = FilenameUtils.removeExtension(containerFSRL.getName());
		this.javaSrcFilename = className + ".java";

		try (ByteProvider decompiledBP = getDecompiledJavaSrcFileEntry(null, monitor)) {
			this.fsIndexHelper = new SingleFileSystemIndexHelper(this, fsFSRL, javaSrcFilename,
				decompiledBP.length(), decompiledBP.getFSRL().getMD5());
		}
	}

	private ByteProvider getDecompiledJavaSrcFileEntry(FSRL targetFSRL, TaskMonitor monitor)
			throws CancelledException, IOException {
		return fsService.getDerivedByteProviderPush(containerFSRL, targetFSRL, javaSrcFilename, -1,
			(os) -> decompileClassFileToStream(os, monitor), monitor);
	}

	private void decompileClassFileToStream(OutputStream os, TaskMonitor monitor)
			throws CancelledException, IOException {
		File tempDir = null;
		try {
			tempDir = FileUtilities.createTempDirectory("JavaClassDecompilerFileSystem");

			File tempClassFile = new File(tempDir, containerFSRL.getName());
			FSUtilities.copyByteProviderToFile(provider, tempClassFile, monitor);

			// tempDestJavaSrcFile (ie. "javaclass.java") contents are automagically
			// created by the Jad process based on the class name it finds inside
			// the binary "javaclass.class" file.  Class, class, class.
			File tempDestJavaSrcFile = new File(tempDir, javaSrcFilename);

			JadProcessWrapper wrapper = new JadProcessWrapper(tempClassFile);
			JadProcessController controller = new JadProcessController(wrapper, className);
			controller.decompile(5, monitor);

			FileUtilities.copyFileToStream(tempDestJavaSrcFile, os, monitor);
		}
		finally {
			FileUtilities.deleteDir(tempDir, monitor);
		}
	}

	public GFile getPayloadFile() {
		return fsIndexHelper.getPayloadFile();
	}

	@Override
	public String getName() {
		return containerFSRL.getName();
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndexHelper.clear();
		provider.close();
	}

	@Override
	public boolean isClosed() {
		return fsIndexHelper.isClosed();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public int getFileCount() {
		return fsIndexHelper.getFileCount();
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndexHelper.lookup(path);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (fsIndexHelper.isPayloadFile(file)) {
			return getDecompiledJavaSrcFileEntry(file.getFSRL(), monitor);
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndexHelper.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		return FileAttributes.of(FileAttribute.create("Class name", className));
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

}
