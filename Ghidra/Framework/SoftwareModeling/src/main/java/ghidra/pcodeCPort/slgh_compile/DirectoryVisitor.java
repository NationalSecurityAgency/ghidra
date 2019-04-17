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
package ghidra.pcodeCPort.slgh_compile;

import java.io.File;
import java.io.FileFilter;
import java.util.*;

public class DirectoryVisitor implements Iterable<File> {
    private final ArrayList<File> startingDirectories;
    private final FileFilter directoryFilter;
    private final FileFilter filter;
    private final boolean compareCase;

    public DirectoryVisitor(File startingDirectory, FileFilter filter) {
        this(startingDirectory, null, filter, true);
    }

    public DirectoryVisitor(File startingDirectory, FileFilter filter,
            boolean compareCase) {
        this(startingDirectory, null, filter, compareCase);
    }

    public DirectoryVisitor(File startingDirectory, FileFilter directoryFilter,
            FileFilter filter) {
        this(startingDirectory, directoryFilter, filter, true);
    }

    public DirectoryVisitor(File startingDirectory, FileFilter directoryFilter,
            FileFilter filter, boolean compareCase) {
        this.startingDirectories = new ArrayList<File>();
        this.startingDirectories.add(startingDirectory);
        this.directoryFilter = directoryFilter;
        this.filter = filter;
        this.compareCase = compareCase;
    }

    public DirectoryVisitor(Collection<File> startingDirectories, FileFilter filter) {
        this(startingDirectories, null, filter, true);
    }

    public DirectoryVisitor(Collection<File> startingDirectories, FileFilter filter,
            boolean compareCase) {
        this(startingDirectories, null, filter, compareCase);
    }

    public DirectoryVisitor(Collection<File> startingDirectories, FileFilter directoryFilter,
            FileFilter filter) {
        this(startingDirectories, directoryFilter, filter, true);
    }

    public DirectoryVisitor(Collection<File> startingDirectories, FileFilter directoryFilter,
            FileFilter filter, boolean compareCase) {
        this.startingDirectories = new ArrayList<File>(startingDirectories);
        this.directoryFilter = directoryFilter;
        this.filter = filter;
        this.compareCase = compareCase;
    }

    public Iterator<File> iterator() {
        return new BreadthFirstDirectoryVisitor(startingDirectories, directoryFilter, filter, compareCase);
    }

    private static class BreadthFirstDirectoryVisitor implements Iterator<File> {
        private final LinkedList<File> directoryQueue = new LinkedList<File>();
        private final LinkedList<File> fileQueue = new LinkedList<File>();
        private final FileFilter directoryFilter;
        private final FileFilter filter;
        private final Comparator<File> comparator;

        private static final Comparator<File> CASE_SENSITIVE = new Comparator<File>() {
            public int compare(File o1, File o2) {
                return o1.getName().compareTo(o2.getName());
            }
        };

        private static final Comparator<File> CASE_INSENSITIVE = new Comparator<File>() {
            public int compare(File o1, File o2) {
                return o1.getName().compareToIgnoreCase(o2.getName());
            }
        };

        private static final FileFilter DIRECTORIES = new FileFilter() {
            public boolean accept(File pathname) {
                return pathname.isDirectory();
            }
        };

        public BreadthFirstDirectoryVisitor(Iterable<File> startingDirectories,
                final FileFilter directoryFilter, FileFilter filter,
                boolean compareCase) {
            this.directoryFilter = directoryFilter == null ? DIRECTORIES
                    : new FileFilter() {
                        public boolean accept(File pathname) {
                            return pathname.isDirectory()
                                    && directoryFilter.accept(pathname);
                        }
                    };
            this.filter = filter;
            comparator = compareCase ? CASE_SENSITIVE : CASE_INSENSITIVE;
            for (File directory : startingDirectories) {
                if (!directory.isDirectory()) {
                    throw new RuntimeException(directory + " is not a directory");
                }
                directoryQueue.addLast(directory);
            }
        }

        private void populateDirectoryQueue(File startingDirectory) {
            File[] subdirectories = startingDirectory.listFiles(directoryFilter);            
            if (subdirectories != null) {
                Arrays.sort(subdirectories, comparator);
                for (File subdirectory : subdirectories) {
                    directoryQueue.addLast(subdirectory);
                }
            }
        }

        private void populateFileQueue(File directory) {
            File[] files = directory.listFiles(filter);            
            if (files != null) {
                Arrays.sort(files, comparator);
                for (File file : files) {
                    fileQueue.addLast(file);
                }
            }
        }

        private void ensureNextFileIsPresentInQueue() {
            while (fileQueue.isEmpty() && !directoryQueue.isEmpty()) {
                File directory = directoryQueue.removeFirst();
                populateDirectoryQueue(directory);
                populateFileQueue(directory);
            }
        }

        public boolean hasNext() {
            ensureNextFileIsPresentInQueue();
            return !fileQueue.isEmpty();
        }

        public File next() {
            ensureNextFileIsPresentInQueue();
            return fileQueue.removeFirst();
        }

        public void remove() {
            throw new UnsupportedOperationException();
        }
    }
}
