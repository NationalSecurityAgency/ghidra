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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.List;
import java.util.SortedMap;

/**
 * This class is an extension of {@link DebugData}.  The purpose of this class is to allow for
 * testing of internal components of {@link AbstractPdb} and external classes that use them.
 * It is not part of the production PDB Reader.
 */
public class DummyDebugData extends DebugData {

	// Private set of these (different from parent class)
	private SortedMap<Long, Long> omapFromSource;
	private List<ImageSectionHeader> imageSectionHeaders;
	private List<ImageSectionHeader> imageSectionHeadersOrig;

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a basic object.
	 *  Note: not all values are initialized.
	 * @param pdb The AbstractPdb foundation for the {@link PdbOldDebugInfo}.
	 */
	DummyDebugData(AbstractPdb pdb) {
		super(pdb);
	}

	//==============================================================================================
	/**
	 * Returns the OMAP_FROM_SOURCE mapping of RVA to RVA
	 * @return the omapFromSource or null if does not exist.
	 */
	@Override
	public SortedMap<Long, Long> getOmapFromSource() {
		return omapFromSource;
	}

	/**
	 * Returns the {@link List}&lt;{@link ImageSectionHeader}&gt;.
	 * @return the imageSectionHeaders or null if does not exist.
	 */
	@Override
	public List<ImageSectionHeader> getImageSectionHeaders() {
		return imageSectionHeaders;
	}

	/**
	 * Returns the {@link List}&lt;{@link ImageSectionHeader}&gt;.
	 * When this return a non-null list the OMAP_FROM_SRC should be
	 * used for remapping global symbols.
	 * @return the imageSectionHeadersOrig or null if does not exist.
	 */
	@Override
	public List<ImageSectionHeader> getImageSectionHeadersOrig() {
		return imageSectionHeadersOrig;
	}

	//==============================================================================================
	/**
	 * Sets the OMAP_FROM_SOURCE mapping of RVA to RVA
	 * @param omapFromSource the OMAP_FROM_SOURCE map
	 */
	public void setOmapFromSource(SortedMap<Long, Long> omapFromSource) {
		this.omapFromSource = omapFromSource;
	}

	/**
	 * Sets the {@link ImageSectionHeader} list
	 * @param imageSectionHeaders {@link ImageSectionHeader} list
	 */
	public void setImageSectionHeaders(List<ImageSectionHeader> imageSectionHeaders) {
		this.imageSectionHeaders = imageSectionHeaders;
	}

	/**
	 * Sets the {@link ImageSectionHeader} original list
	 * @param imageSectionHeadersOrig {@link ImageSectionHeader} list
	 */
	public void setImageSectionHeadersOrig(List<ImageSectionHeader> imageSectionHeadersOrig) {
		this.imageSectionHeadersOrig = imageSectionHeadersOrig;
	}

}
