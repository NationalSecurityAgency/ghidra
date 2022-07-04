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
package ghidra.server;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;

/**
 * <code>CommandWatcher</code> watches the command queue directory (~admin) for new
 * command files and initiates their processing in the order they were issued.
 * The use of the {@link WatchService} is limited to detection of command file creation
 * and invokes {@link RepositoryManager#processCommandQueue()} when one or more
 * command files have been queued or an {@link StandardWatchEventKinds#OVERFLOW}
 * event occurs.
 */
public class CommandWatcher implements Runnable {

	private RepositoryManager repositoryMgr;
	private Path cmdDirPath;
	private WatchService watcher;

	CommandWatcher(RepositoryManager repositoryMgr) throws IOException {
		this.repositoryMgr = repositoryMgr;

		watcher = FileSystems.getDefault().newWatchService();
		cmdDirPath = CommandProcessor.getOrCreateCommandDir(repositoryMgr).toPath();
		cmdDirPath.register(watcher, StandardWatchEventKinds.ENTRY_CREATE);
	}

	void dispose() {
		try {
			watcher.close();
		}
		catch (IOException e) {
			// ignore
		}
	}

	@Override
	public void run() {

		RepositoryManager.log.info("Command watcher started");
		while (true) {

			// wait for key to be signaled
			WatchKey key;
			try {
				key = watcher.take();
			}
			catch (InterruptedException | ClosedWatchServiceException e) {
				break;
			}

			boolean processCommands = false;
			for (WatchEvent<?> event : key.pollEvents()) {
				WatchEvent.Kind<?> kind = event.kind();

				// An OVERFLOW event can occur if events are lost or discarded.
				if (kind == StandardWatchEventKinds.OVERFLOW) {
					processCommands = true;
					continue;
				}

				// The filename is the
				// context of the event.
				@SuppressWarnings("unchecked")
				WatchEvent<Path> ev = (WatchEvent<Path>) event;
				Path filename = ev.context();

				// Verify that the new file is a command file - ignore all others
				Path child = cmdDirPath.resolve(filename);
				File file = child.toFile();

				// Only care about command files which still exist since
				// they may have already been consumed
				if (CommandProcessor.CMD_FILE_FILTER.accept(child.toFile()) && file.exists()) {
					processCommands = true;
				}
			}

			if (processCommands) {
				try {
					repositoryMgr.processCommandQueue();
				}
				catch (Exception e) {
					RepositoryManager.log.error("Command processing failure: " + e.toString(), e);
				}
			}

			// Reset the key to receive further watch events.  
			// Key will become invalid when closed/disposed
			boolean valid = key.reset();
			if (!valid) {
				break;
			}
		}
		RepositoryManager.log.info("Command watcher terminated.");
	}

}
