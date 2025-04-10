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
package ghidra.plugin.importer;

import java.net.MalformedURLException;
import java.util.*;
import java.util.function.BiFunction;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.main.datatable.ProjectDataTablePanel;
import ghidra.framework.model.*;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

/**
 * An in-memory index of FSRL-to-domainfile in the current project.
 */
public class ProjectIndexService implements DomainFolderChangeListener {

	public static ProjectIndexService getInstance() {
		return SingletonHolder.instance;
	}

	private static class SingletonHolder {
		private static final ProjectIndexService instance = new ProjectIndexService();
	}

	public enum IndexType {
		MD5("Executable MD5"), FSRL("FSRL");

		private String metadataKey;

		IndexType(String metadataKey) {
			this.metadataKey = metadataKey;
		}

		public String getMetadataKey() {
			return metadataKey;
		}
	}

	/**
	 * @param indexType IndexType enum
	 * @param mappingFunc bifunc that returns value that will be used to lookup the file
	 * @param indexedFiles map of index keyvalue to fileId (either string or list of strings)
	 *
	 */
	record IndexInfo(IndexType indexType,
			BiFunction<DomainFile, Map<String, String>, Object> mappingFunc,
			Map<Object, Object> indexedFiles) {
		IndexInfo(IndexType indexType,
				BiFunction<DomainFile, Map<String, String>, Object> mappingFunc) {
			this(indexType, mappingFunc, new HashMap<>());
		}
	}

	private Project project;
	private List<IndexInfo> indexes;

	private ProjectIndexService() {
		this.indexes = List.of(new IndexInfo(IndexType.MD5, this::getMD5),
			new IndexInfo(IndexType.FSRL, this::getFSRL));
	}

	public synchronized void clearProject() {
		if (project != null) {
			project.getProjectData().removeDomainFolderChangeListener(this);
			for (IndexInfo index : indexes) {
				index.indexedFiles.clear();
			}
			project = null;
		}
	}

	public void setProject(Project newProject, TaskMonitor monitor) {
		synchronized (this) {
			if (newProject == project) {
				return;
			}
			clearProject();
			project = newProject;

			if (project != null) {
				indexes = List.of(new IndexInfo(IndexType.MD5, this::getMD5),
					new IndexInfo(IndexType.FSRL, this::getFSRL));
				ProjectData projectData = project.getProjectData();
				projectData.removeDomainFolderChangeListener(this);
				projectData.addDomainFolderChangeListener(this);
			}
		}

		if (newProject != null) {
			// index outside of sync lock to allow concurrent lookups
			indexProject(newProject.getProjectData(), monitor);
		}
	}

	@Override
	public void domainFileAdded(DomainFile file) {
		indexFile(file);
	}

	@Override
	public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
		removeFile(fileID);
	}

	private void indexProject(ProjectData projectData, TaskMonitor monitor) {
		int fileCount = projectData.getFileCount();
		if (fileCount < 0 || fileCount > ProjectDataTablePanel.MAX_FILE_COUNT) {
			return;
		}
		monitor.initialize(fileCount, "Indexing Project Metadata");
		for (DomainFile df : ProjectDataUtils.descendantFiles(projectData.getRootFolder())) {
			monitor.incrementProgress();
			if (monitor.isCancelled()) {
				break;
			}
			indexFile(df);
			if (monitor.getProgress() % 10 == 0) {
				Swing.allowSwingToProcessEvents();
			}
		}
	}

	private String getMD5(DomainFile file, Map<String, String> metadata) {
		return metadata.get(IndexType.MD5.metadataKey);
	}

	private FSRL getFSRL(DomainFile file, Map<String, String> metadata) {
		String fsrlStr = metadata.get(IndexType.FSRL.metadataKey);
		try {
			return fsrlStr != null ? FSRL.fromString(fsrlStr).withMD5(null) : null;
		}
		catch (MalformedURLException e) {
			return null;
		}
	}

	public synchronized List<DomainFile> lookupFiles(IndexType keyType, Object keyValue) {
		IndexInfo index = indexes.get(keyType.ordinal());
		Object fileInfo = index.indexedFiles.get(keyValue);
		List<String> fileIds;
		if (fileInfo instanceof String fileIdStr) {
			fileIds = List.of(fileIdStr);
		}
		else if (fileInfo instanceof List fileInfoList) {
			fileIds = fileInfoList;
		}
		else {
			fileIds = List.of();
		}
		return fileIds.stream()
				.map(fileId -> project.getProjectData().getFileByID(fileId))
				.filter(Objects::nonNull)
				.toList();
	}

	public DomainFile findFirstByFSRL(FSRL fsrl) {
		fsrl = fsrl.withMD5(null);
		List<DomainFile> files = lookupFiles(IndexType.FSRL, fsrl);
		return !files.isEmpty() ? files.get(0) : null;
	}

	private synchronized void indexFile(DomainFile file) {
		Map<String, String> metadata = file.getMetadata();
		for (IndexInfo index : indexes) {
			Object indexedValue = index.mappingFunc.apply(file, metadata);
			if (indexedValue != null) {
				Object fileInfo = index.indexedFiles.get(indexedValue);
				if (fileInfo == null) {
					index.indexedFiles.put(indexedValue, file.getFileID());
				}
				else if (fileInfo instanceof List<?> fileInfoList) {
					((List<String>) fileInfoList).add(file.getFileID());
				}
				else if (fileInfo instanceof String prevFileId) {
					String newFileId = file.getFileID();
					if (newFileId.equals(prevFileId)) {
						// don't need to do anything
						continue;
					}
					List<String> fileInfoList = new ArrayList<>();
					fileInfoList.add(prevFileId);
					fileInfoList.add(newFileId);
					index.indexedFiles.put(indexedValue, fileInfoList);
				}
			}
		}
	}

	private synchronized void removeFile(String fileId) {
		// brute force search through all entries to remove the file
		for (IndexInfo index : indexes) {
			for (Iterator<Object> it = index.indexedFiles.values().iterator(); it
					.hasNext();) {
				Object fileInfo = it.next();
				if (fileInfo instanceof String fileIdStr && fileIdStr.equals(fileId)) {
					it.remove();
				}
				else if (fileInfo instanceof List fileInfoList) {
					fileInfoList.remove(fileId);
					if (fileInfoList.isEmpty()) {
						it.remove();
					}
				}
			}
		}
	}

}
