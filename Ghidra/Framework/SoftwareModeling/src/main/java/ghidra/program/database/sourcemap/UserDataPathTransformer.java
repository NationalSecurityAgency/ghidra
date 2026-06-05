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
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.sourcemap.SourcePathTransformRecord;
import ghidra.program.model.sourcemap.SourcePathTransformer;

/**
 * An implementation of {@link SourcePathTransformer} that stores transform information using
 * {@link ProgramUserData}.  This means that transform information will be stored locally
 * but not checked in to a shared project.<br>
 * <p>
 * Use the static method {@link UserDataPathTransformer#getPathTransformer} to get the transformer 
 * for a program. <br>
 * <p>
 * Synchronization policy: {@code userData}, {@code pathMap}, {@code fileMap}, and
 * {@code programsToTransformers} must be protected.
 */
public class UserDataPathTransformer implements SourcePathTransformer, DomainObjectClosedListener {

	private Program program;
	private static final String USER_FILE_TRANSFORM_PREFIX = "USER_FILE_TRANSFORM_";
	private static final String USER_PATH_TRANSFORM_PREFIX = "USER_DIRECTORY_TRANSFORM_";
	private TreeMap<String, String> pathMap;
	private Map<String, String> fileMap;
	private ProgramUserData userData;
	private static final String FILE_SCHEME = "file";
	private static HexFormat hexFormat = HexFormat.of();
	private static HashMap<Program, UserDataPathTransformer> programsToTransformers =
		new HashMap<>();

	/**
	 * Returns the path transformer for {@code program}
	 * @param program program
	 * @return path transformer
	 */
	public static synchronized SourcePathTransformer getPathTransformer(Program program) {
		if (program == null) {
			return null;
		}
		return programsToTransformers.computeIfAbsent(program, p -> new UserDataPathTransformer(p));
	}

	/**
	 * Throws an {@link IllegalArgumentException} if {@code directory} is not
	 * a valid, normalized directory path (with forward slashes).
	 * @param directory path to validate
	 */
	public static void validateDirectoryPath(String directory) {
		if (StringUtils.isBlank(directory)) {
			throw new IllegalArgumentException("Blank directory path");
		}
		URI uri;
		try {
			uri = new URI(FILE_SCHEME, null, directory, null).normalize();
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException(e.getMessage());
		}
		String normalizedPath = uri.getPath();
		if (!normalizedPath.endsWith("/")) {
			throw new IllegalArgumentException(directory + " is not a directory path");
		}
		if (!directory.equals(normalizedPath)) {
			throw new IllegalArgumentException(directory + " is not normalized");
		}
		return;
	}

	private UserDataPathTransformer(Program program) {
		this.program = program;
		userData = program.getProgramUserData();
		pathMap = new TreeMap<>(Collections.reverseOrder(UserDataPathTransformer::compareStrings));
		fileMap = new HashMap<>();
		reloadMaps();
		program.addCloseListener(this);
	}

	@Override
	public void domainObjectClosed(DomainObject dobj) {
		synchronized (UserDataPathTransformer.class) {
			programsToTransformers.remove(program);
		}
	}

	@Override
	public synchronized void addFileTransform(SourceFile sourceFile, String path) {
		SourceFile validated = new SourceFile(path);
		if (!validated.getPath().equals(path)) {
			throw new IllegalArgumentException("path not normalized");
		}
		int txId = userData.startTransaction();
		String sourceString = getString(sourceFile);
		try {
			userData.setStringProperty(USER_FILE_TRANSFORM_PREFIX + sourceString,
				path);
		}
		finally {
			userData.endTransaction(txId);
		}
		fileMap.put(sourceString, path);
	}

	@Override
	public synchronized void removeFileTransform(SourceFile sourceFile) {
		int txId = userData.startTransaction();
		String sourceString = getString(sourceFile);
		try {
			userData.removeStringProperty(USER_FILE_TRANSFORM_PREFIX + getString(sourceFile));
		}
		finally {
			userData.endTransaction(txId);
		}
		fileMap.remove(sourceString);
	}

	@Override
	public synchronized void addDirectoryTransform(String sourceDir, String targetDir) {
		validateDirectoryPath(sourceDir);
		validateDirectoryPath(targetDir);
		int txId = userData.startTransaction();
		try {
			userData.setStringProperty(USER_PATH_TRANSFORM_PREFIX + sourceDir, targetDir);
		}
		finally {
			userData.endTransaction(txId);
		}
		pathMap.put(sourceDir, targetDir);
	}

	@Override
	public synchronized void removeDirectoryTransform(String sourceDir) {
		int txId = userData.startTransaction();
		try {
			userData.removeStringProperty(USER_PATH_TRANSFORM_PREFIX + sourceDir);
		}
		finally {
			userData.endTransaction(txId);
		}
		pathMap.remove(sourceDir);
	}

	@Override
	public synchronized String getTransformedPath(SourceFile sourceFile,
			boolean useExistingAsDefault) {
		String sourceFileString = getString(sourceFile);
		String mappedFile = fileMap.get(sourceFileString);
		if (mappedFile != null) {
			return mappedFile;
		}
		String path = sourceFile.getPath();
		for (String src : pathMap.keySet()) {
			if (path.startsWith(src)) {
				return pathMap.get(src) + path.substring(src.length());
			}
		}
		return useExistingAsDefault ? path : null;
	}

	@Override
	public synchronized List<SourcePathTransformRecord> getTransformRecords() {
		List<SourcePathTransformRecord> transformRecords = new ArrayList<>();
		for (Entry<String, String> entry : pathMap.entrySet()) {
			transformRecords
					.add(new SourcePathTransformRecord(entry.getKey(), null, entry.getValue()));
		}
		for (Entry<String, String> entry : fileMap.entrySet()) {
			String sourceFileString = entry.getKey();
			transformRecords.add(new SourcePathTransformRecord(sourceFileString,
				getSourceFile(sourceFileString), entry.getValue()));
		}
		return transformRecords;
	}

	private static int compareStrings(String left, String right) {
		int leftLength = left.length();
		int rightLength = right.length();
		if (leftLength != rightLength) {
			return Integer.compare(leftLength, rightLength);
		}
		return StringUtils.compare(left, right);
	}

	private void reloadMaps() {
		pathMap.clear();
		fileMap.clear();
		for (String key : userData.getStringPropertyNames()) {
			if (key.startsWith(USER_PATH_TRANSFORM_PREFIX)) {
				String value = userData.getStringProperty(key, null);
				if (StringUtils.isBlank(value)) {
					throw new AssertionError("blank value for path " + key);
				}
				pathMap.put(key.substring(USER_PATH_TRANSFORM_PREFIX.length()), value);
				continue;
			}
			if (key.startsWith(USER_FILE_TRANSFORM_PREFIX)) {
				String value = userData.getStringProperty(key, null);
				if (StringUtils.isBlank(value)) {
					throw new AssertionError("blank value for file " + key);
				}
				fileMap.put(key.substring(USER_FILE_TRANSFORM_PREFIX.length()), value);
			}
		}
	}

	private String getString(SourceFile sourceFile) {
		StringBuilder sb = new StringBuilder(sourceFile.getIdType().name());
		sb.append("#");
		sb.append(hexFormat.formatHex(sourceFile.getIdentifier()));
		sb.append("#");
		sb.append(sourceFile.getPath());
		return sb.toString();
	}

	private SourceFile getSourceFile(String sourceFileString) {
		int firstHash = sourceFileString.indexOf("#");
		SourceFileIdType type = SourceFileIdType.valueOf(sourceFileString.substring(0, firstHash));
		int secondHash = sourceFileString.indexOf("#", firstHash + 1);
		byte[] identifier =
			hexFormat.parseHex(sourceFileString.subSequence(firstHash + 1, secondHash));
		String path = sourceFileString.substring(secondHash + 1);
		return new SourceFile(path, type, identifier);
	}

}
