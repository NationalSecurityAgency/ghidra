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
package ghidra.program.database.sourcemap;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.BigEndianDataConverter;

/**
 * A SourceFile is an immutable object representing a source file.  It contains an
 * absolute path along with an optional {@link SourceFileIdType} and identifier. 
 * For example, if the id type is {@link SourceFileIdType#MD5}, the identifier would
 * be the md5 sum of the source file (stored as a byte array).
 * <p>
 * Note: path parameters are assumed to be absolute file paths with forward slashes as the
 * separator.  For other cases, e.g. windows paths, consider the static convenience methods in
 * the {@code SourceFileUtils} class.
 * <p>
 * Note: you can use {@code SourceFileUtils.hexStringToByteArray} to convert hex Strings to byte 
 * arrays. You can use {@code SourceFileUtils.longToByteArray} to convert long values to the
 * appropriate byte arrays.
 */
public final class SourceFile implements Comparable<SourceFile> {

	private static final String FILE_SCHEME = "file";
	private static HexFormat hexFormat = HexFormat.of();
	private final String path;
	private final String filename;
	private final SourceFileIdType idType;
	private final byte[] identifier;
	private final int hash;
	private final String idDisplayString;
	

	/**
	 * Constructor requiring only a path.  The path will be normalized (see {@link URI#normalize})
	 * The id type will be set to {@code SourceFileIdType.NONE} and the identifier will 
	 * be set to an array of length 0.
	 * 
	 * @param path path
	 */
	public SourceFile(String path) {
		this(path, SourceFileIdType.NONE, null, true);
	}

	/**
	 * Constructor. The path will be normalized (see {@link URI#normalize}).
	 * <p>
	 * Note: if {@code type} is {@code SourceFileIdType.NONE}, the {@code identifier}
	 * parameter is ignored.
	 * <p>
	 * Note: use {@code SourceFileUtils.longToByteArray} to convert a {@code long} value
	 * to the appropriate {@code byte} array.
	 * @param path path
	 * @param type id type
	 * @param identifier id
	 */
	public SourceFile(String path, SourceFileIdType type, byte[] identifier) {
		this(path, type, identifier, true);
	}

	/**
	 * Constructor.  The path will be normalized (see {@link URI#normalize}).
	 * <p>
	 * Note: if {@code type} is {@code SourceFileIdType.NONE}, the {@code identifier}
	 * parameter is ignored.
	 * <p>
	 * IMPORTANT: only pass {@code false} as {@code validate} parameter if you are certain that
	 * validation can be skipped, e.g., you are creating a SourceFile from information
	 * read out of the database which was validated at insertion. 
	 * @param pathToValidate path
	 * @param type sourcefile id type
	 * @param identifier identifier
	 * @param validate true if params should be validated
	 */
	SourceFile(String pathToValidate, SourceFileIdType type, byte[] identifier, boolean validate) {
		if (validate) {
			if (StringUtils.isBlank(pathToValidate)) {
				throw new IllegalArgumentException("pathToValidate cannot be null or blank");
			}
			try {
				URI uri = new URI(FILE_SCHEME, null, pathToValidate, null).normalize();
				path = uri.getPath();
				if (path.endsWith("/")) {
					throw new IllegalArgumentException(
						"SourceFile URI must represent a file (not a directory)");
				}
			}
			catch (URISyntaxException e) {
				throw new IllegalArgumentException("path not valid: " + e.getMessage());
			}
		}
		else {
			path = pathToValidate;
		}
		this.idType = type;
		filename = path.substring(path.lastIndexOf("/") + 1);
		this.identifier = validateAndCopyIdentifier(identifier);
		hash = computeHashcode();
		idDisplayString = computeIdDisplayString();
	}

	/**
	 * Returns a file URI for this SourceFile.
	 * @return uri
	 */
	public URI getUri() {
		try {
			return new URI(FILE_SCHEME, null, path, null);
		}
		catch (URISyntaxException e) {
			throw new AssertionError("URISyntaxException on validated path");
		}
	}

	/**
	 * Returns the path
	 * @return path
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Returns the filename
	 * @return filename
	 */
	public String getFilename() {
		return filename;
	}

	/**
	 * Returns the source file identifier type
	 * @return id type
	 */
	public SourceFileIdType getIdType() {
		return idType;
	}

	/**
	 * Returns (a copy of) the identifier
	 * @return identifier
	 */
	public byte[] getIdentifier() {
		byte[] copy = new byte[identifier.length];
		System.arraycopy(identifier, 0, copy, 0, identifier.length);
		return copy;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof SourceFile otherFile)) {
			return false;
		}
		if (!path.equals(otherFile.path)) {
			return false;
		}
		if (!idType.equals(otherFile.idType)) {
			return false;
		}
		return Arrays.equals(identifier, otherFile.identifier);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(path);
		if (idType.equals(SourceFileIdType.NONE)) {
			return sb.toString();
		}
		sb.append(" [");
		sb.append(idType.name());
		sb.append("=");
		sb.append(getIdAsString());
		sb.append("]");
		return sb.toString();
	}

	@Override
	public int compareTo(SourceFile sourceFile) {
		int comp = path.compareTo(sourceFile.path);
		if (comp != 0) {
			return comp;
		}
		comp = idType.compareTo(sourceFile.idType);
		if (comp != 0) {
			return comp;
		}
		return Arrays.compare(identifier, sourceFile.identifier);
	}

	/**
	 * Returns a String representation of the identifier
	 * @return id display string
	 */
	public String getIdAsString() {
		return idDisplayString;
	}

	// immutable object - compute hash and cache
	private int computeHashcode() {
		int result = path.hashCode();
		result = 31 * result + idType.hashCode();
		result = 31 * result + Arrays.hashCode(identifier);
		return result;
	}

	private byte[] validateAndCopyIdentifier(byte[] array) {
		if (array == null || idType == SourceFileIdType.NONE) {
			array = new byte[0];
		}
		if (array.length > SourceFileIdType.MAX_LENGTH) {
			throw new IllegalArgumentException(
				"identifier array too long; max is " + SourceFileIdType.MAX_LENGTH);
		}
		if (idType.getByteLength() != 0 && idType.getByteLength() != array.length) {
			throw new IllegalArgumentException(
				"identifier array has wrong length for " + idType.name());
		}
		byte[] copy = new byte[array.length];
		System.arraycopy(array, 0, copy, 0, array.length);
		return copy;
	}

	private String computeIdDisplayString() {
		switch (idType) {
			case NONE:
				return StringUtils.EMPTY;
			case TIMESTAMP_64:
				return Instant.ofEpochMilli(BigEndianDataConverter.INSTANCE.getLong(identifier))
						.toString();
			default:
				return hexFormat.formatHex(identifier);
		}
	}

}
