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
package ghidra.formats.gfilesystem.annotations;

import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.factory.GFileSystemFactory;

import java.lang.annotation.*;

/**
 * Specifies the info needed of a {@link GFileSystem} implementation.
 * <p>
 * <ul>
 * <li>{@link #type()} is required.</li>
 * <li>{@link #description()} is optional.</li>
 * <li>{@link #factory()} is required.</li>
 * </ul>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface FileSystemInfo {
	/**
	 * The 'type' of this filesystem, a short 1 word, lowercase string used in FSRLs to reference
	 * this filesystem, "[a-z0-9]+" only.
	 * @return Short 1 word lowercase String.
	 */
	String type();

	/**
	 * A longer description of this filesystem.
	 * <p>
	 * @return Free form description string, defaults to empty string if not set.
	 */
	String description() default "";

	/**
	 * The {@link GFileSystemFactory} class that will be responsible for probing and
	 * creating instances of this filesystem.
	 *
	 * @return Class that implements {@link GFileSystemFactory}
	 */
	Class<? extends GFileSystemFactory<?>>factory();

	/**
	 * The relative priority of filesystems during probing.
	 * <p>
	 * Higher numeric values are considered before lower values.
	 * <p>
	 * @return integer that specifies the relative ordering of filesystems during
	 * probing.
	 */
	int priority() default PRIORITY_DEFAULT;

	public static final int PRIORITY_DEFAULT = 0;
	public static final int PRIORITY_HIGH = 10;
	public static final int PRIORITY_LOW = -10;
	public static final int PRIORITY_LOWEST = Integer.MIN_VALUE;

}
