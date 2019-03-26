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

import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.GFileSystemBase;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.Msg;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Comparator;
import java.util.regex.Pattern;

/**
 * Holds information read from a {@link FileSystemInfo} annotation.
 * <p>
 */
public class FileSystemInfoRec {
	private static final Pattern FSTYPE_VALID_REGEX = Pattern.compile("[a-z0-9]+");

	private final String type;
	private final String description;
	private final int priority;
	private final Class<? extends GFileSystem> fsClass;
	private final GFileSystemFactory<?> factory;

	/**
	 * A static {@link Comparator} that will order {@link FileSystemInfoRec} by their
	 * {@link FileSystemInfoRec#getPriority() priority}, with the highest priority
	 * elements sorted to the beginning of the list.
	 */
	public static final Comparator<FileSystemInfoRec> BY_PRIORITY = (o1, o2) -> {
		return Integer.compare(o2.priority, o1.priority);
	};

	/**
	 * Instantiate a new {@link FileSystemInfoRec} from the information found in the
	 * {@link FileSystemInfo} annotation attached to the specified Class.
	 *
	 * @param fsClazz class to query for file system info.
	 * @return new {@link FileSystemInfoRec}, or null if the class doesn't have
	 * valid file system meta data.
	 */
	public static FileSystemInfoRec fromClass(Class<? extends GFileSystem> fsClazz) {
		FileSystemInfo fsi = fsClazz.getAnnotation(FileSystemInfo.class);
		if (fsi == null) {
			return null;
		}
		String fsType = fsi.type();
		if (!FSTYPE_VALID_REGEX.matcher(fsType).matches()) {
			Msg.error(FileSystemInfoRec.class, "Bad GFileSystem type specified for " +
				fsClazz.getName() + ": " + fsType + ", skipping.");
			return null;
		}

		Class<? extends GFileSystemFactory<?>> factoryClass = fsi.factory();
		GFileSystemFactory<?> factory = null;
		try {
			Constructor<? extends GFileSystemFactory<?>> ctor = factoryClass.getConstructor();
			factory = ctor.newInstance();
		}
		catch (InstantiationException | IllegalAccessException | NoSuchMethodException
				| SecurityException | IllegalArgumentException | InvocationTargetException e) {
			Msg.error(FileSystemInfoRec.class,
				"Error when creating GFileSystem factory " + factoryClass.getName(), e);
			return null;
		}

		// Hack to allow GFileSystemBaseFactory to know which fsclass is using it
		// so instances can be created by the single GFileSystemBaseFactory impl.
		if (factory instanceof GFileSystemBaseFactory) {
			((GFileSystemBaseFactory) factory).setFileSystemClass(
				(Class<? extends GFileSystemBase>) fsClazz);
		}

		FileSystemInfoRec fsir =
			new FileSystemInfoRec(fsType, fsi.description(), fsi.priority(), fsClazz, factory);

		return fsir;
	}

	private FileSystemInfoRec(String type, String description, int priority,
			Class<? extends GFileSystem> fsClass, GFileSystemFactory<?> factory) {
		this.type = type;
		this.description = description;
		this.priority = priority;
		this.fsClass = fsClass;
		this.factory = factory;
	}

	/**
	 * Filesystem 'type', ie. "file", or "zip", etc.
	 *
	 * @return type string
	 */
	public String getType() {
		return type;
	}

	/**
	 * Filesystem description, ie. "XYZ Vendor Filesystem Type 1"
	 *
	 * @return description string
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Filesystem relative priority.
	 * <p>
	 * See {@link FileSystemInfo#priority()}.
	 *
	 * @return priority int
	 */
	public int getPriority() {
		return priority;
	}

	/**
	 * The {@link Class} of the filesystem implementation.
	 *
	 * @return {@link GFileSystem} derived class.
	 */
	public Class<? extends GFileSystem> getFSClass() {
		return fsClass;
	}

	/**
	 * The {@link GFileSystemFactory} instance that will create new filesystem
	 * instances when needed.
	 *
	 * @return {@link GFileSystemFactory} for this filesystem
	 */
	public GFileSystemFactory<?> getFactory() {
		return factory;
	}
}
