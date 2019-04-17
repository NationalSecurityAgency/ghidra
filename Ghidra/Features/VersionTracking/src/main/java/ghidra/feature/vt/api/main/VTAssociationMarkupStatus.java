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
package ghidra.feature.vt.api.main;

/**
 * Class the indicates an overview, or high-level status, for the markup items 
 * within an association.  This status can be used to query the state of the markup items.  For
 * example, {@link #hasUnexaminedMarkup()} will indicate of some markup items have not yet been
 * applied or marked as considered.
 */
public class VTAssociationMarkupStatus implements Comparable<VTAssociationMarkupStatus> {
	private static int INITIALIZED = 0x1;
	private static int HAS_UNEXAMINED = 0x2;
	private static int HAS_APPLIED = 0x4;
	private static int HAS_REJECTED = 0x8;
	private static int HAS_DONT_CARE = 0x10;
	private static int HAS_DONT_KNOW = 0x20;
	private static int HAS_ERRORS = 0x40;

	private int status;

	public VTAssociationMarkupStatus() {
		this.status = 0;
	}

	public VTAssociationMarkupStatus(int status) {
		this.status = status;
	}

	public VTAssociationMarkupStatus(boolean hasUnexamined, boolean hasApplied,
			boolean hasRejected, boolean hasDontCare, boolean hasDontKnow, boolean hasErrors) {
		status = INITIALIZED; // status has valid INFO
		status |= hasUnexamined ? HAS_UNEXAMINED : 0;
		status |= hasApplied ? HAS_APPLIED : 0;
		status |= hasRejected ? HAS_REJECTED : 0;
		status |= hasDontCare ? HAS_DONT_CARE : 0;
		status |= hasDontKnow ? HAS_DONT_KNOW : 0;
		status |= hasErrors ? HAS_ERRORS : 0;
	}

	/**
	 * Returns true if the status has been initialized.  It is initialized when an association is
	 * accepted.
	 * @return  true if the status has been initialized.
	 */
	public boolean isInitialized() {
		return (status & INITIALIZED) != 0;
	}

	/**
	 * Returns true if there is one or markup items that have not had a decision made on them.
	 * @return true if there is one or markup items that have not had a decision made on them.
	 */
	public boolean hasUnexaminedMarkup() {
		return (status & HAS_UNEXAMINED) != 0;
	}

	/**
	 * Returns true if there is one or markup items that have been applied.
	 * @return true if there is one or markup items that have been applied.
	 */
	public boolean hasAppliedMarkup() {
		return (status & HAS_APPLIED) != 0;
	}

	/**
	 * Returns true if there is one or markup items that have been rejected.
	 * @return true if there is one or markup items that have been rejected.
	 */
	public boolean hasRejectedMarkup() {
		return (status & HAS_REJECTED) != 0;
	}

	/**
	 * Returns true if there is one or markup items that have been marked as "Don't Care".
	 * @return true if there is one or markup items that have been marked as "Don't Care".
	 */
	public boolean hasDontCareMarkup() {
		return (status & HAS_DONT_CARE) != 0;
	}

	/**
	 * Returns true if there is one or markup items that have been marked as "Don't Know".
	 * @return true if there is one or markup items that have been marked as "Don't Know".
	 */
	public boolean hasDontKnowMarkup() {
		return (status & HAS_DONT_KNOW) != 0;
	}

	/**
	 * Returns true if there is one or markup items that encountered an error when attempting to apply.
	 * @return true if there is one or markup items that encountered an error when attempting to apply.
	 */
	public boolean hasErrors() {
		return (status & HAS_ERRORS) != 0;
	}

	/**
	 * Returns the combined bit fields for the various status bits.
	 * @return the combine bit fields value for the status.
	 */
	public int getStatusValue() {
		return status;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof VTAssociationMarkupStatus)) {
			return false;
		}
		return status == ((VTAssociationMarkupStatus) obj).status;
	}

	@Override
	public int hashCode() {
		return status;
	}

	/**
	 * Returns true if all the markup items have been applied
	 * @return true if all the markup items have been applied
	 */
	public boolean isFullyApplied() {
		return status == INITIALIZED || status == (INITIALIZED | HAS_APPLIED);
	}

	@Override
	public int compareTo(VTAssociationMarkupStatus o) {
		return status - o.status;
	}

	/**
	 * Returns a description of this status, detailing the various status values.
	 * @return  a description of this status, detailing the various status values.
	 */
	public String getDescription() {
		StringBuffer buf = new StringBuffer();
		if (hasUnexaminedMarkup()) {
			buf.append("Has one or more unexamined markup items.\n");
		}
		if (hasAppliedMarkup()) {
			buf.append("Has one or more applied markup items.\n");
		}
		if (hasErrors()) {
			buf.append("Has one or more markup items that failed to apply.\n");
		}
		if (hasDontCareMarkup()) {
			buf.append("Has one or more \"Don't Care\" markup items.\n");
		}
		if (hasDontKnowMarkup()) {
			buf.append("Has one or more \"Don't Know\" markup items.\n");
		}
		return buf.toString();
	}

	@Override
	public String toString() {
		return "Markup Status: " + getDescription();
	}
}
