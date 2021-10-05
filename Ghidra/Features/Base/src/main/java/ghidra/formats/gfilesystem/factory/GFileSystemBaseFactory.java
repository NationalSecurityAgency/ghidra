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

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link GFileSystemFactory} implementation that probes and creates instances of
 * {@link GFileSystemBase} which use the legacy filesystem lifecycle pattern.
 * <p>
 * For each operation, this factory will mint a new instance of a GFileSystemBase-derived
 * fs, using its 3 param constructor, and call its isValid() or open().
 * <p>
 * After an isValid() call, the newly minted filesystem instance is thrown away.
 * <p>
 * This class requires special support in the {@link FileSystemFactoryMgr} to push
 * the fsClass into each factory instance after it is constructed.
 *
 */
public class GFileSystemBaseFactory
		implements GFileSystemFactoryByteProvider<GFileSystemBase>, GFileSystemProbeByteProvider {

	private Class<? extends GFileSystemBase> fsClass;
	private static final Class<?>[] FS_CTOR_PARAM_TYPES =
		new Class[] { String.class, ByteProvider.class };

	public GFileSystemBaseFactory() {
		// nada
	}

	public void setFileSystemClass(Class<? extends GFileSystemBase> fsClass) {
		this.fsClass = fsClass;
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

		try {
			FSRL containerFSRL = byteProvider.getFSRL();
			Constructor<? extends GFileSystemBase> ctor =
				fsClass.getConstructor(FS_CTOR_PARAM_TYPES);
			GFileSystemBase fs = ctor.newInstance(containerFSRL.getName(), byteProvider);
			fs.setFilesystemService(fsService);
			// do NOT close fs here because that would close the byteProvider
			return fs.isValid(monitor);
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new IOException("Error when probing filesystem " + fsClass.getName(), e);
		}
	}

	@Override
	public GFileSystemBase create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		try {
			FSRL containerFSRL = byteProvider.getFSRL();
			Constructor<? extends GFileSystemBase> ctor =
				fsClass.getConstructor(FS_CTOR_PARAM_TYPES);
			GFileSystemBase fs = ctor.newInstance(containerFSRL.getName(), byteProvider);
			fs.setFilesystemService(fsService);
			fs.setFSRL(targetFSRL);
			try {
				if (!fs.isValid(monitor)) {
					throw new IOException("Error when creating new filesystem " +
						fsClass.getName() + ", isvalid failed");
				}
				fs.open(monitor);

				GFileSystemBase successFS = fs;
				fs = null;
				return successFS;
			}
			finally {
				if (fs != null) {
					fs.close();
				}
			}
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new IOException("Error when opening filesystem " + fsClass.getName(), e);
		}
		catch (RuntimeException e) {
			throw new IOException("Runtime exception when opening filesystem " + fsClass.getName(),
				e);
		}
	}

}
