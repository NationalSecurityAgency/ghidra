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
package ghidra.framework.main.projectdata.actions;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.swing.AbstractButton;

import org.junit.*;

import docking.ActionContext;
import docking.test.AbstractDockingTest;
import docking.widgets.OptionDialog;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.model.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;
import util.CollectionUtils;

public class DeleteProjectFilesTaskTest extends AbstractDockingTest {
	private TestDummyDomainFolder root;
	private DomainFolder a;
	private DomainFolder b;
	private DomainFolder c;
	private DomainFolder d;
	private DomainFolder e;
	private DomainFolder aa;
	private DomainFolder ee;
	private DomainFolder eee;
	private DomainFolder empty;

	private Set<DomainFolder> folders;
	private Set<DomainFile> files;
	private ProjectDataDeleteAction deleteAction;
	private DeleteProjectFilesTask task;

	private CountDownLatch taskEnded;

	@Before
	public void setUp() throws Exception {
		root = new TestDummyDomainFolder(null, "root");
		a = root.createFolder("a");
		b = root.createFolder("b");
		c = root.createFolder("c");
		d = root.createFolder("d");
		e = root.createFolder("e");
		createFiles(root, 10);
		createFiles(a, 10);
		createFiles(b, 10);
		createFiles(c, 10);
		createFiles(d, 10);
		aa = a.createFolder("aa");
		createFiles(aa, 10);

		empty = root.createFolder("empty");
		ee = e.createFolder("ee");
		eee = ee.createFolder("eee");
		createFiles(eee, 1);
	}

	@After
	public void tearDown() {

		closeAllWindows();
		taskEnded.countDown();

		waitForCondition(() -> {
			closeAllWindows();
			return taskEnded.getCount() == 0;
		});
	}

	@Test
	public void testConfirmDialogAppears() {

		DomainFile file = a.getFile("prog_3");
		createDeleteAction(null, CollectionUtils.asSet(file));
		runAction();

		assertDialog("Confirm Delete");
		assertDialogButtons("OK", "Cancel");
		cancelDelete();

		assertNotNull("Delete not cancelled", a.getFile("prog_5"));
	}

	@Test
	public void testDeleteOneFileAndThereIsNoSummary() {
		DomainFile file = a.getFile("prog_3");
		createDeleteAction(null, CollectionUtils.asSet(file));
		runAction();
		confirmDelete();

		waitForTask();
		assertNull(a.getFile("prog_3"));
		assertSummaryDialog(false);
	}

	@Test
	public void testDeleteTwoFilessuccessfullyAndThereIsNoSummary() {
		DomainFile file1 = a.getFile("prog_3");
		DomainFile file2 = a.getFile("prog_6");

		createDeleteAction(null, CollectionUtils.asSet(file1, file2));
		runAction();
		confirmDelete();

		assertSummaryDialog(false);

		waitForTask();
		assertNull(a.getFile("prog_3"));
		assertNull(a.getFile("prog_6"));
		assertNotNull(a.getFile("prog_5"));
	}

	@Test
	public void testDeleteTwoFilesWithOneFailureAndThereIsSummary() throws IOException {
		DomainFile file1 = a.getFile("prog_3");
		DomainFile file2 = a.getFile("prog_6");
		file2.setReadOnly(true);

		createDeleteAction(null, CollectionUtils.asSet(file1, file2));
		runAction();
		confirmDelete();

		answerDialog("Confirm Delete Read-only File", "No"); // don't delete read-only file 
		assertSummaryDialog(true);

		waitForTask();
		assertNull(a.getFile("prog_3"));
		assertNotNull(a.getFile("prog_6"));
		assertNotNull(a.getFile("prog_5"));
	}

	@Test
	public void testDeleteExtraConfirmForReadOnlyFileAndThenDeleteIt() throws IOException {
		DomainFile file1 = a.getFile("prog_3");
		DomainFile file2 = a.getFile("prog_6");
		file2.setReadOnly(true);

		createDeleteAction(null, CollectionUtils.asSet(file1, file2));
		runAction();
		confirmDelete();

		answerDialog("Confirm Delete Read-only File", "Yes");
		assertSummaryDialog(false);

		waitForTask();
		assertNull(a.getFile("prog_3"));
		assertNull(a.getFile("prog_6"));
		assertNotNull(a.getFile("prog_5"));
	}

	@Test
	public void testDeleteExtraConfirmForVersionedFileAndThenDeleteIt() {
		DomainFile file1 = a.getFile("prog_3");
		DomainFile file2 = a.getFile("prog_6");
		((TestDummyDomainFile) file2).setVersioned();

		createDeleteAction(null, CollectionUtils.asSet(file1, file2));
		runAction();
		confirmDelete();

		answerDialog("Confirm Delete Versioned File", "Yes"); // don't delete versioned file
		assertSummaryDialog(false);

		waitForTask();
		assertNull(a.getFile("prog_3"));
		assertNull(a.getFile("prog_6"));
		assertNotNull(a.getFile("prog_5"));
	}

	@Test
	public void testNotifyCantDeleteForVersionedCheckedOutFile() {
		DomainFile file1 = a.getFile("prog_3");
		DomainFile file2 = a.getFile("prog_6");
		((TestDummyDomainFile) file2).setCheckedOut();

		createDeleteAction(null, CollectionUtils.asSet(file1, file2));
		runAction();
		confirmDelete();

		answerDialog("Delete Not Allowed", "OK");
		assertSummaryDialog(true);

		waitForTask();
		assertNull(a.getFile("prog_3"));
		assertNotNull(a.getFile("prog_6"));
		assertNotNull(a.getFile("prog_5"));
	}

	@Test
	public void testNotifyForDeleteInUseFile() {
		DomainFile file1 = a.getFile("prog_3");
		DomainFile file2 = a.getFile("prog_6");
		((TestDummyDomainFile) file2).setInUse();

		createDeleteAction(null, CollectionUtils.asSet(file1, file2));
		runAction();
		confirmDelete();

		answerDialog("Delete Not Allowed", "OK");

		assertSummaryDialog(true);
		waitForTask();

		assertNull(a.getFile("prog_3"));
		assertNotNull(a.getFile("prog_6"));
		assertNotNull(a.getFile("prog_5"));
	}

	@Test
	public void testApplyToAll() throws IOException {
		DomainFile file1 = a.getFile("prog_1");
		DomainFile file2 = a.getFile("prog_2");
		DomainFile file3 = a.getFile("prog_3");
		DomainFile file4 = a.getFile("prog_4");
		file1.setReadOnly(true);
		file2.setReadOnly(true);
		file4.setReadOnly(true);

		createDeleteAction(null, CollectionUtils.asSet(file1, file2, file3, file4));
		runAction();
		confirmDelete();

		answerDialog("Confirm Delete Read-only File", "Apply to all");

		closeDialog("Yes");
		assertSummaryDialog(false); // all files deleted, so no summary

		waitForTask();
		assertNull(a.getFile("prog_1"));
		assertNull(a.getFile("prog_2"));
		assertNull(a.getFile("prog_3"));
		assertNull(a.getFile("prog_4"));
	}

	@Test
	public void testDeleteFolder() {
		createDeleteAction(CollectionUtils.asSet(a, b), null);
		runAction();
		confirmDelete();

		assertSummaryDialog(false); // no files deleted, so no summary
		waitForTask();

		assertNull(root.getFolder("a"));
		assertNull(root.getFolder("b"));
		assertNotNull(root.getFolder("c"));
	}

	@Test
	public void testDeleteEmptyFolder() {
		createDeleteAction(CollectionUtils.asSet(empty), null);
		runAction();
		confirmDelete("empty folder");

		assertSummaryDialog(false); // no files deleted, so no summary
		waitForTask();

		assertNull(root.getFolder("empty"));
	}

	@Test
	public void testDeleteFolder_OnlyFolderSelected_WithFileInSubFolder() {
		// 
		// 'ee' has only a single folder: eee; eee has a single file
		//
		createDeleteAction(CollectionUtils.asSet(ee), null);

		runAction();
		confirmDelete();

		assertSummaryDialog(false); // no files deleted, so no summary
		waitForTask();

		assertNull(root.getFolder("e/ee"));
	}

	@Test
	public void testDeleteFolderWhereNotAllFilesInFolderDeleted() throws IOException {
		DomainFile file = a.getFile("prog_1");
		file.setReadOnly(true);
		createDeleteAction(CollectionUtils.asSet(a, b), null);
		runAction();
		confirmDelete();

		answerDialog("Confirm Delete Read-only File", "No");
		assertSummaryDialog(true);

		waitForTask();
		assertNotNull(root.getFolder("a"));
		assertEquals(1, root.getFolder("a").getFiles().length);
		assertNull(root.getFolder("b"));
		assertNotNull(root.getFolder("c"));
	}

	@Test
	public void testSelectedFileContainedInSelectedFolder() {
		createDeleteAction(CollectionUtils.asSet(b), CollectionUtils.asSet(b.getFile("prog_1")));
		runAction();

		confirmDelete();

		// folder "b" has 10 files, one of which is also selected, so should get 10, not 11
		assertEquals(10, task.getFileCount());
	}

	@Test
	public void testDeleteFolderAndParentFolderInSelection() {
		createDeleteAction(CollectionUtils.asSet(a, aa), null);
		runAction();
		confirmDelete();
		assertEquals(20, task.getFileCount());
	}

	@Test
	public void testReadOnlyFileSelectedAndInSelectedFolderAsksOnlyOnce() throws IOException {
		DomainFile file = b.getFile("prog_1");
		file.setReadOnly(true);

		createDeleteAction(CollectionUtils.asSet(b, c), CollectionUtils.asSet(file));
		runAction();
		confirmDelete();

		answerDialog("Confirm Delete Read-only File", "No");

		assertSummaryDialog(true);
	}

	@Test
	public void testCancelReadOnlyReallyCancels() throws IOException {
		DomainFile file1 = b.getFile("prog_1");
		DomainFile file2 = b.getFile("prog_2");
		file1.setReadOnly(true);
		file2.setReadOnly(true);
		createDeleteAction(null, CollectionUtils.asSet(file1, file2));
		runAction();
		confirmDelete();

		answerDialog("Confirm Delete Read-only File", "Cancel");

		assertSummaryDialog(true);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void answerDialog(String title, String buttonText) {

		OptionDialog dialog = assertDialog(title);
		pressButtonByText(dialog, buttonText);
	}

	private void confirmDelete() {
		confirmDelete("Are you sure");
	}

	private void confirmDelete(String messageText) {
		// return "Are you sure you want to delete the selected empty folder(s)?";

		OptionDialog dialog = waitForDialog();
		assertEquals("Confirm Delete", dialog.getTitle());
		String message = dialog.getMessage();
		assertTrue(
			"Dialog has the wrong message.  Expected: " + messageText + ", found: " + message,
			message.contains(messageText));
		pressButtonByText(dialog, "OK");
		waitForSwing();
	}

	private void cancelDelete() {
		OptionDialog dialog = waitForDialog();
		assertEquals("Confirm Delete", dialog.getTitle());
		pressButtonByText(dialog, "Cancel");
		waitForSwing();
	}

	private void assertSummaryDialog(boolean expected) {

		if (!expected) {
			waitForSwing();
			OptionDialog dialog = getDialogComponent(OptionDialog.class);
			assertNull("Summary dialog should not be visible", dialog);
			return;
		}

		OptionDialog dialog = waitForDialog();
		if (dialog == null) {
			fail("Expect summary dialog, but did not get one");
		}

		if (dialog != null) {
			assertEquals("Delete Files Summary", dialog.getTitle());
			closeDialog("OK");
		}
	}

	private OptionDialog assertDialog(String title) {
		OptionDialog optionDialog = waitForDialog();
		assertTitle(optionDialog, title);
		return optionDialog;
	}

	private void closeDialog(String buttonText) {
		OptionDialog dialog = waitForDialog();
		pressButtonByText(dialog, buttonText);
		waitForSwing();
	}

	private void assertDialogButtons(String... buttonNames) {
		OptionDialog dialog = waitForDialog();
		for (String buttonName : buttonNames) {
			AbstractButton button = findAbstractButtonByText(dialog.getComponent(), buttonName);
			if (button == null) {
				fail("Can't find expected button: " + buttonName);
			}
		}
	}

	private void assertTitle(OptionDialog optionDialog, String title) {
		assertEquals(title, optionDialog.getTitle());
	}

	private OptionDialog waitForDialog() {
		return waitForDialogComponent(OptionDialog.class);
	}

	private void waitForTask() {
		try {
			taskEnded.await(1, TimeUnit.SECONDS);
		}
		catch (InterruptedException ie) {
			failWithException("Unexpected InterruptedException waiting for task;", ie);
		}
	}

	private void createDeleteAction(Set<DomainFolder> theFolders, Set<DomainFile> theFiles) {
		taskEnded = new CountDownLatch(1);
		folders = theFolders != null ? theFolders : Collections.emptySet();
		files = theFiles != null ? theFiles : Collections.emptySet();

		ProjectDataDeleteAction action = new ProjectDataDeleteAction("Owner", "Group") {

			@Override
			DeleteProjectFilesTask createDeleteTask(ProjectDataContext context,
					Set<DomainFile> myFiles, Set<DomainFolder> myFolders, int fileCount) {

				task = new DeleteProjectFilesTask(myFolders, myFiles, fileCount, null);
				task.addTaskListener(new TaskListener() {

					@Override
					public void taskCompleted(Task t) {
						taskEnded.countDown();
					}

					@Override
					public void taskCancelled(Task t) {
						taskEnded.countDown();
					}
				});
				return task;
			}
		};

		this.deleteAction = action;
	}

	private void runAction() {

		ActionContext context = new ProjectDataContext(/*provider*/null, /*project data*/null,
			/*context object*/ null, CollectionUtils.asList(folders), CollectionUtils.asList(files),
			null, true);
		performAction(deleteAction, context, false);
		waitForSwing();
	}

	private void createFiles(DomainFolder folder, int count) throws Exception {
		for (int i = 0; i < count; i++) {
			folder.createFile("prog_" + i, (DomainObject) null, null);
		}
	}

}
