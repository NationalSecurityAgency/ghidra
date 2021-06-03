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

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Statically scoped mugger that handles the dirty work of probing for and creating
 * {@link GFileSystem} instances.
 * <p>
 * Auto-discovers all {@link GFileSystem} instances in the classpath that have a
 * {@link FileSystemInfo} annotation.
 * <p>
 */
public class FileSystemFactoryMgr {

	/**
	 * <p>
	 * @return The single global {@link FileSystemFactoryMgr} instance.
	 */
	public static FileSystemFactoryMgr getInstance() {
		return Singleton.instance;
	}

	/**
	 * A way to delay initialization of the global FileSystemFactoryMgr until it is first used.
	 */
	private static class Singleton {
		private static final FileSystemFactoryMgr instance = new FileSystemFactoryMgr();
	}

	private int largestBytesRequired = 0;
	private List<FileSystemInfoRec> sortedFactories = new ArrayList<>();
	private Map<String, FileSystemInfoRec> fsByType = new HashMap<>();

	/**
	 * Private constructor.  Use {@link FileSystemFactoryMgr#getInstance()} to retrieve
	 * the singleton.
	 */
	private FileSystemFactoryMgr() {

		// for each GFileSystem class found in classpath, get its factory info
		for (Class<? extends GFileSystem> fsClass : ClassSearcher.getClasses(GFileSystem.class)) {
			addFactory(fsClass);
		}
		Collections.sort(sortedFactories, FileSystemInfoRec.BY_PRIORITY);
	}

	private void addFactory(Class<? extends GFileSystem> fsClass) {
		FileSystemInfoRec fsir = FileSystemInfoRec.fromClass(fsClass);
		if (fsir == null) {
			Msg.error(this, "No valid FileSystemInfo found for " + fsClass.getName());
			return;
		}
		if (fsByType.containsKey(fsir.getType())) {
			FileSystemInfoRec prevFSI = fsByType.get(fsir.getType());
			Msg.error(this,
				"GFileSystem type '" + fsir.getType() + "' registered more than one time: " +
					fsClass.getName() + ", " + prevFSI.getFSClass().getName() +
					", ommitting second instance.");
			return;
		}

		if (fsir.getFactory() instanceof GFileSystemFactoryIgnore) {
			// don't register any filesystem that uses this factory
			return;
		}
		if (fsir.getFactory() instanceof GFileSystemProbeBytesOnly) {
			GFileSystemProbeBytesOnly pbo = (GFileSystemProbeBytesOnly) fsir.getFactory();
			if (pbo.getBytesRequired() > GFileSystemProbeBytesOnly.MAX_BYTESREQUIRED) {
				Msg.error(this,
					"GFileSystemProbeBytesOnly for " + fsClass.getName() +
						" specifies too large value for bytes_required: " + pbo.getBytesRequired() +
						", skipping this probe.");
			}
			else {
				largestBytesRequired = Math.max(largestBytesRequired, pbo.getBytesRequired());
			}
		}

		fsByType.put(fsir.getType(), fsir);
		sortedFactories.add(fsir);
	}

	/**
	 * Returns a list of all registered filesystem implementation descriptions.
	 *
	 * @return list of strings
	 */
	public List<String> getAllFilesystemNames() {
		//@formatter:off
		return fsByType
				.keySet()
				.stream()
				.map(fsType -> fsByType.get(fsType).getDescription())
				.sorted(String::compareToIgnoreCase)
				.collect(Collectors.toList());
		//@formatter:on
	}

	/**
	 * Returns the file system type of the specified {@link GFileSystem} class.
	 *
	 * @param fsClass Class to inspect
	 * @return String file system type, from the {@link FileSystemInfo#type()} annotation.
	 */
	public String getFileSystemType(Class<? extends GFileSystem> fsClass) {
		FileSystemInfo fsi = fsClass.getAnnotation(FileSystemInfo.class);
		return (fsi != null) && (fsByType.get(fsi.type()) != null) ? fsi.type() : null;
	}

	/**
	 * Creates a new {@link GFileSystem} instance when the filesystem type is already
	 * known.
	 * <p>
	 *
	 * @param fsType filesystem type string, ie. "file", "zip".
	 * @param containerFSRL {@link FSRL} of the containing file.
	 * @param containerFile {@link File} the containing file.
	 * @param fsService reference to the {@link FileSystemService} instance.
	 * @param monitor {@link TaskMonitor} to use for canceling and updating progress.
	 * @return new {@link GFileSystem} instance.
	 * @throws IOException if error when opening the filesystem or unknown fsType.
	 * @throws CancelledException if the user canceled the operation.
	 */
	public GFileSystem mountFileSystem(String fsType, FSRL containerFSRL, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		FileSystemInfoRec fsir = fsByType.get(fsType);
		if (fsir == null) {
			throw new IOException("Unknown file system type " + fsType);
		}

		GFileSystem result = mountUsingFactory(fsir, containerFSRL, containerFile, null,
			containerFSRL.makeNested(fsType), fsService, monitor);

		return result;
	}

	private GFileSystem mountUsingFactory(FileSystemInfoRec fsir, FSRL containerFSRL,
			File containerFile, ByteProvider byteProvider, FSRLRoot targetFSRL,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		GFileSystem result = null;
		boolean bpTaken = false;
		try {
			if (fsir.getFactory() instanceof GFileSystemFactoryFull) {
				byteProvider =
					(byteProvider == null) ? makeBP(containerFile, containerFSRL) : byteProvider;
				bpTaken = true;
				result = ((GFileSystemFactoryFull<?>) fsir.getFactory()).create(containerFSRL,
					targetFSRL, byteProvider, containerFile, fsService, monitor);
			}
			else if (fsir.getFactory() instanceof GFileSystemFactoryWithFile) {
				result = ((GFileSystemFactoryWithFile<?>) fsir.getFactory()).create(containerFSRL,
					targetFSRL, containerFile, fsService, monitor);
			}
			// add additional GFileSystemFactoryXYZ support blocks here
		}
		finally {
			if (byteProvider != null && !bpTaken) {
				byteProvider.close();
			}
		}

		return result;
	}

	/**
	 * Returns true if the specified file contains a supported {@link GFileSystem}.
	 * <p>
	 * @param containerFSRL {@link FSRL} of the containing file.
	 * @param containerFile {@link File} the containing file.
	 * @param fsService reference to the {@link FileSystemService} instance.
	 * @param monitor {@link TaskMonitor} to use for canceling and updating progress.
	 * @return {@code true} if the file seems to contain a filesystem, {@code false} if it does not.
	 * @throws IOException if error when accessing the containing file
	 * @throws CancelledException if the user canceled the operation
	 */
	public boolean test(FSRL containerFSRL, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

		int pboByteCount = Math.min(
			(int) Math.min(containerFile.length(), GFileSystemProbeBytesOnly.MAX_BYTESREQUIRED),
			largestBytesRequired);

		try (ByteProvider bp = new RandomAccessByteProvider(containerFile, containerFSRL)) {
			byte[] startBytes = bp.readBytes(0, pboByteCount);
			for (FileSystemInfoRec fsir : sortedFactories) {
				try {
					if (fsir.getFactory() instanceof GFileSystemProbeBytesOnly) {
						GFileSystemProbeBytesOnly factoryProbe =
							(GFileSystemProbeBytesOnly) fsir.getFactory();
						if (factoryProbe.getBytesRequired() <= startBytes.length) {
							if (factoryProbe.probeStartBytes(containerFSRL, startBytes)) {
								return true;
							}
						}
					}
					if (fsir.getFactory() instanceof GFileSystemProbeWithFile) {
						GFileSystemProbeWithFile factoryProbe =
							(GFileSystemProbeWithFile) fsir.getFactory();
						if (factoryProbe.probe(containerFSRL, containerFile, fsService, monitor)) {
							return true;
						}
					}
					if (fsir.getFactory() instanceof GFileSystemProbeFull) {
						GFileSystemProbeFull factoryProbe =
							(GFileSystemProbeFull) fsir.getFactory();
						if (factoryProbe.probe(containerFSRL, bp, containerFile, fsService,
							monitor)) {
							return true;
						}
					}
				}
				catch (IOException e) {
					Msg.trace(this, "File system probe error for " + fsir.getDescription() +
						" with " + containerFSRL, e);
				}
			}
		}
		return false;
	}

	/**
	 * Probes the specified file for a supported {@link GFileSystem} implementation, and
	 * if found, creates a new filesystem instance.
	 * <p>
	 *
	 * @param containerFSRL {@link FSRL} of the containing file.
	 * @param containerFile {@link File} the containing file.
	 * @param fsService reference to the {@link FileSystemService} instance.
	 * @param conflictResolver {@link FileSystemProbeConflictResolver conflict resolver} to
	 * use when more than one {@link GFileSystem} implementation can handle the specified
	 * file.
	 * @param monitor {@link TaskMonitor} to use for canceling and updating progress.
	 * @return new {@link GFileSystem} instance or null not supported.
	 * @throws IOException if error accessing the containing file
	 * @throws CancelledException if the user cancels the operation
	 */
	public GFileSystem probe(FSRL containerFSRL, File containerFile, FileSystemService fsService,
			FileSystemProbeConflictResolver conflictResolver, TaskMonitor monitor)
			throws IOException, CancelledException {

		return probe(containerFSRL, containerFile, fsService, conflictResolver,
			FileSystemInfo.PRIORITY_LOWEST, monitor);
	}

	private ByteProvider makeBP(File containerFile, FSRL containerFSRL) throws IOException {
		return new SynchronizedByteProvider(
			new RandomAccessByteProvider(containerFile, containerFSRL));
	}

	/**
	 * Probes the specified file for a supported {@link GFileSystem} implementation, and
	 * if found, creates a new filesystem instance.
	 * <p>
	 *
	 * @param containerFSRL {@link FSRL} of the containing file.
	 * @param containerFile {@link File} the containing file.
	 * @param fsService reference to the {@link FileSystemService} instance.
	 * @param conflictResolver {@link FileSystemProbeConflictResolver conflict resolver} to
	 * use when more than one {@link GFileSystem} implementation can handle the specified
	 * file.
	 * @param priorityFilter limits the probe to filesystems that have a {@link FileSystemInfo#priority()}
	 * greater than or equal to this value.  Use {@link FileSystemInfo#PRIORITY_LOWEST} to
	 * include all filesystem implementations.
	 * @param monitor {@link TaskMonitor} to use for canceling and updating progress.
	 * @return new {@link GFileSystem} instance or null not supported.
	 * @throws IOException if error accessing the containing file
	 * @throws CancelledException if the user cancels the operation
	 */
	public GFileSystem probe(FSRL containerFSRL, File containerFile, FileSystemService fsService,
			FileSystemProbeConflictResolver conflictResolver, int priorityFilter,
			TaskMonitor monitor) throws IOException, CancelledException {

		conflictResolver = (conflictResolver == null) ? FileSystemProbeConflictResolver.CHOOSEFIRST
				: conflictResolver;

		ByteProvider probeBP = makeBP(containerFile, containerFSRL);
		try {
			int pboByteCount = Math.min(
				(int) Math.min(containerFile.length(), GFileSystemProbeBytesOnly.MAX_BYTESREQUIRED),
				largestBytesRequired);

			byte[] startBytes = probeBP.readBytes(0, pboByteCount);
			List<FileSystemInfoRec> probeMatches = new ArrayList<>();
			for (FileSystemInfoRec fsir : sortedFactories) {
				try {
					if (fsir.getPriority() < priorityFilter) {
						break;
					}
					if (fsir.getFactory() instanceof GFileSystemProbeBytesOnly) {
						GFileSystemProbeBytesOnly factoryProbe =
							(GFileSystemProbeBytesOnly) fsir.getFactory();
						if (factoryProbe.getBytesRequired() <= startBytes.length) {
							if (factoryProbe.probeStartBytes(containerFSRL, startBytes)) {
								probeMatches.add(fsir);
								continue;
							}
						}
					}
					if (fsir.getFactory() instanceof GFileSystemProbeWithFile) {
						GFileSystemProbeWithFile factoryProbe =
							(GFileSystemProbeWithFile) fsir.getFactory();
						if (factoryProbe.probe(containerFSRL, containerFile, fsService, monitor)) {
							probeMatches.add(fsir);
							continue;
						}
					}
					if (fsir.getFactory() instanceof GFileSystemProbeFull) {
						GFileSystemProbeFull factoryProbe =
							(GFileSystemProbeFull) fsir.getFactory();
						if (factoryProbe.probe(containerFSRL, probeBP, containerFile, fsService,
							monitor)) {
							probeMatches.add(fsir);
							continue;
						}
					}
				}
				catch (IOException e) {
					Msg.trace(this, "File system probe error for " + fsir.getDescription() +
						" with " + containerFSRL, e);
				}
			}

			monitor.setMessage("Choosing filesystem");
			FileSystemInfoRec fsir = conflictResolver.resolveFSIR(probeMatches);
			if (fsir == null) {
				return null;
			}

			ByteProvider mountBP = probeBP;
			probeBP = null;
			GFileSystem fs = mountUsingFactory(fsir, containerFSRL, containerFile, mountBP,
				containerFSRL.makeNested(fsir.getType()), fsService, monitor);
			monitor.setMessage("Found file system " + fs.getDescription());
			return fs;
		}
		finally {
			if (probeBP != null) {
				probeBP.close();
			}
		}

	}

}
