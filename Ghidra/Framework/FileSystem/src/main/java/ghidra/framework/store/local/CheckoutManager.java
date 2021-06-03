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
package ghidra.framework.store.local;

import java.io.*;
import java.util.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import ghidra.framework.store.*;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;

/**
 * <code>CheckoutManager</code> manages checkout data for a versioned
 * LocalFolderItem. Checkout data is maintained within the file 'checkout.dat'
 * located within the items data directory.
 */
class CheckoutManager {

	static final String CHECKOUTS_FILE = "checkout.dat";

	private LocalFolderItem item;
	private long nextCheckoutId = 1;

	// checkouts maps long checkoutId to ItemCheckoutStatus objects
	private Map<Long, ItemCheckoutStatus> checkouts;

	/**
	 * Constructor.
	 * 
	 * @param item folder item
	 * @param create if true an empty checkout data file is written, else the
	 *            initial data is read from the file.
	 * @throws IOException
	 */
	CheckoutManager(LocalFolderItem item, boolean create) throws IOException {
		this.item = item;
		if (create) {
			checkouts = new HashMap<>();
			writeCheckoutsFile();
		}
	}

	/**
	 * Returns the file which contains checkout data.
	 */
	private File getCheckoutsFile() {
		return new File(item.getDataDir(), CHECKOUTS_FILE);
	}

	/**
	 * Requests a new checkout for the associated item.
	 * 
	 * @param checkoutType type of checkout
	 * @param user name of user requesting checkout
	 * @param version item version to be checked-out
	 * @return checkout data or null if exclusive checkout denied due to
	 *         existing checkouts.
	 * @throws IOException if checkout fails
	 */
	synchronized ItemCheckoutStatus newCheckout(CheckoutType checkoutType, String user, int version,
			String projectPath) throws IOException {
		validate();
		if (checkoutType == null) {
			throw new IllegalArgumentException("checkoutType must be specified");
		}
		ItemCheckoutStatus[] coList = getAllCheckouts();
		if (coList.length != 0) {
			if (checkoutType != CheckoutType.NORMAL) {
				return null;
			}
			if (coList[0].getCheckoutType() == CheckoutType.TRANSIENT) {
				throw new ExclusiveCheckoutException(
					"File temporarily checked out exclusively by: " + coList[0].getUser());
			}
			if (coList[0].getCheckoutType() == CheckoutType.EXCLUSIVE) {
				throw new ExclusiveCheckoutException(
					"File checked out exclusively to another project by: " + coList[0].getUser());
			}
		}
		ItemCheckoutStatus coStatus = new ItemCheckoutStatus(nextCheckoutId++, checkoutType, user,
			version, (new Date()).getTime(), projectPath);
		checkouts.put(coStatus.getCheckoutId(), coStatus);
		if (checkoutType != CheckoutType.TRANSIENT) {
			writeCheckoutsFile();
		}
		item.log("checkout (" + coStatus.getCheckoutId() + ") granted", user);
		return coStatus;
	}

	/**
	 * Update the version associated with the specified checkout
	 * 
	 * @param checkoutId checkout ID to be updated
	 * @param version item version to be associated with checkout
	 */
	synchronized void updateCheckout(long checkoutId, int version) throws IOException {
		validate();
		ItemCheckoutStatus coStatus = checkouts.remove(checkoutId);
		if (coStatus != null) {
			CheckoutType checkoutType = coStatus.getCheckoutType();
			coStatus = new ItemCheckoutStatus(checkoutId, checkoutType, coStatus.getUser(), version,
				(new Date()).getTime(), coStatus.getProjectPath());
			checkouts.put(checkoutId, coStatus);
			if (checkoutType != CheckoutType.TRANSIENT) {
				try {
					writeCheckoutsFile();
				}
				catch (IOException e) {
					item.log("ERROR! failed to update checkout version", coStatus.getUser());
				}
			}
		}
	}

	/**
	 * Terminate the specified checkout
	 * 
	 * @param checkoutId checkout ID
	 * @throws IOException
	 */
	synchronized void endCheckout(long checkoutId) throws IOException {
		validate();
		ItemCheckoutStatus coStatus = checkouts.remove(checkoutId);
		if (coStatus != null) {
			item.log("checkout (" + checkoutId + ") ended", coStatus.getUser());
			if (coStatus.getCheckoutType() != CheckoutType.TRANSIENT) {
				boolean success = false;
				try {
					writeCheckoutsFile();
					success = true;
				}
				finally {
					if (!success) {
						checkouts.put(checkoutId, coStatus);
					}
				}
			}
		}
	}

	/**
	 * Returns true if the specified version of the associated item is
	 * checked-out.
	 * 
	 * @param version the specific version to check for checkouts.
	 */
	synchronized boolean isCheckedOut(int version) throws IOException {
		validate();
		for (long id : checkouts.keySet()) {
			ItemCheckoutStatus coStatus = checkouts.get(id);
			if (coStatus.getCheckoutVersion() == version) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true if the any version of the associated item is checked-out.
	 */
	synchronized boolean isCheckedOut() throws IOException {
		validate();
		return checkouts.size() != 0;
	}

	/**
	 * Returns the checkout data corresponding to the specified checkout ID.
	 * Null is returned if checkout ID is not found.
	 * 
	 * @param checkoutId checkout ID
	 */
	synchronized ItemCheckoutStatus getCheckout(long checkoutId) throws IOException {
		validate();
		return checkouts.get(checkoutId);
	}

	/**
	 * Returns the checkout data for all existing checkouts of the associated
	 * item.
	 */
	synchronized ItemCheckoutStatus[] getAllCheckouts() throws IOException {
		validate();
		List<ItemCheckoutStatus> list = new ArrayList<>(checkouts.values());
		Collections.sort(list, (a, b) -> (int) (a.getCheckoutId() - b.getCheckoutId()));
		return list.toArray(new ItemCheckoutStatus[list.size()]);
	}

	/**
	 * If validationRequired is true and the checkout data file has been
	 * updated, the checkout data will be re-initialized from the file. This is
	 * undesirable and is only required when multiple instances of a
	 * LocalFolderItem are used for a specific item path (e.g., unit testing).
	 */
	private void validate() throws IOException {
		if (LocalFileSystem.isRefreshRequired()) {
			checkouts = null;
		}
		if (checkouts == null) {
			long oldNextCheckoutId = nextCheckoutId;
			boolean success = false;
			try {
				readCheckoutsFile();
				success = true;
			}
			finally {
				if (!success) {
					nextCheckoutId = oldNextCheckoutId;
					checkouts = null;
				}
			}
		}
	}

	/**
	 * Read data from checkout file.
	 * 
	 * @throws IOException
	 */
	@SuppressWarnings("unchecked")
	private void readCheckoutsFile() throws IOException {

		checkouts = new HashMap<>();

		File checkoutsFile = getCheckoutsFile();
		if (!checkoutsFile.exists()) {
			return;
		}

		FileInputStream istream = new FileInputStream(checkoutsFile);
		BufferedInputStream bis = new BufferedInputStream(istream);
		try {
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Document doc = sax.build(bis);
			Element root = doc.getRootElement();

			String nextId = root.getAttributeValue("NEXT_ID");
			try {
				nextCheckoutId = Long.parseLong(nextId);
			}
			catch (NumberFormatException e) {
				throw new IOException("Invalid checkouts file: " + checkoutsFile);
			}

			List<Element> elementList = root.getChildren("CHECKOUT");
			Iterator<Element> iter = elementList.iterator();
			while (iter.hasNext()) {
				ItemCheckoutStatus coStatus = parseCheckoutElement(iter.next());
				checkouts.put(coStatus.getCheckoutId(), coStatus);
			}
		}
		catch (org.jdom.JDOMException je) {
			throw new InvalidObjectException("Invalid checkouts file: " + checkoutsFile);
		}
		finally {
			istream.close();
		}
	}

	/**
	 * Parse checkout element from file.
	 * 
	 * @param coElement checkout data element
	 * @return checkout data for specified element
	 * @throws JDOMException
	 */
	ItemCheckoutStatus parseCheckoutElement(Element coElement) throws JDOMException {
		try {
			long checkoutId = Long.parseLong(coElement.getAttributeValue("ID"));
			String user = coElement.getAttributeValue("USER");
			int checkoutVersion = Integer.parseInt(coElement.getAttributeValue("VERSION"));
			long time = Long.parseLong(coElement.getAttributeValue("TIME"));
			String projectPath = coElement.getAttributeValue("PROJECT");
			String val = coElement.getAttributeValue("EXCLUSIVE");
			boolean exclusive = val != null ? Boolean.valueOf(val).booleanValue() : false;
			CheckoutType checkoutType = exclusive ? CheckoutType.EXCLUSIVE : CheckoutType.NORMAL;

			return new ItemCheckoutStatus(checkoutId, checkoutType, user, checkoutVersion, time,
				projectPath);
		}
		catch (NumberFormatException e) {
			throw new JDOMException("Bad CHECKOUT element");
		}
	}

	/**
	 * Write checkout data file.
	 * 
	 * @throws IOException
	 */
	private void writeCheckoutsFile() throws IOException {

		// Output checkouts as XML
		Element root = new Element("CHECKOUT_LIST");
		root.setAttribute("NEXT_ID", Long.toString(nextCheckoutId));

		for (ItemCheckoutStatus status : checkouts.values()) {
			// TRANSIENT checkout data must not be persisted - the existence
			// of such checkouts is retained in-memory only
			if (status.getCheckoutType() != CheckoutType.TRANSIENT) {
				root.addContent(getCheckoutElement(status));
			}
		}

		File checkoutsFile = getCheckoutsFile();

		// Store checkout data in temporary file
		File tmpFile = new File(checkoutsFile.getParentFile(), checkoutsFile.getName() + ".new");
		tmpFile.delete();
		FileOutputStream ostream = new FileOutputStream(tmpFile);
		BufferedOutputStream bos = new BufferedOutputStream(ostream);

		try {
			Document doc = new Document(root);
			XMLOutputter xmlout = new GenericXMLOutputter();
			xmlout.output(doc, bos);
		}
		finally {
			bos.close();
		}

		// Rename files
		File oldFile = null;
		if (checkoutsFile.exists()) {
			oldFile = new File(checkoutsFile.getParentFile(), checkoutsFile.getName() + ".bak");
			oldFile.delete();
			if (!checkoutsFile.renameTo(oldFile)) {
				throw new IOException("Failed to update checkouts: " + item.getPathName());
			}
		}
		if (!tmpFile.renameTo(checkoutsFile)) {
			if (oldFile != null) {
				oldFile.renameTo(checkoutsFile);
			}
			throw new IOException("Failed to update checkouts: " + item.getPathName());
		}
		if (oldFile != null) {
			oldFile.delete();
		}
	}

	/**
	 * Build checkout data element
	 * 
	 * @param coStatus checkout data
	 * @return checkout data element
	 */
	Element getCheckoutElement(ItemCheckoutStatus coStatus) {
		Element element = new Element("CHECKOUT");
		element.setAttribute("ID", Long.toString(coStatus.getCheckoutId()));
		element.setAttribute("USER", coStatus.getUser());
		element.setAttribute("VERSION", Integer.toString(coStatus.getCheckoutVersion()));
		element.setAttribute("TIME", Long.toString(coStatus.getCheckoutTime()));
		String projectPath = coStatus.getProjectPath();
		if (projectPath != null) {
			element.setAttribute("PROJECT", projectPath);
		}
		element.setAttribute("EXCLUSIVE",
			Boolean.toString(coStatus.getCheckoutType() == CheckoutType.EXCLUSIVE));
		return element;
	}

}
