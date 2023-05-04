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
package classrecovery;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;

public class GccTypeinfo extends Typeinfo {
	
	private static final String CLASS_TYPEINFO_NAMESPACE = "__class_type_info";
	private static final String SI_CLASS_TYPEINFO_NAMESPACE = "__si_class_type_info";
	private static final String VMI_CLASS_TYPEINFO_NAMESPACE = "__vmi_class_type_info";
	
	boolean isSpecialTypeinfo;
	GccTypeinfo inheritedSpecialTypeinfo = null; 
	Address vtableAddress;
	boolean inProgramMemory;
	String mangledNamespaceString = null;
	long inheritanceFlagValue;

	List<BaseTypeinfo> baseTypeinfos = new ArrayList<BaseTypeinfo>();
	
	public GccTypeinfo(Address address, Namespace classNamespace, boolean isSpecialTypeinfo, boolean inProgramMemory){
	
	super(address, classNamespace);
		this.isSpecialTypeinfo = isSpecialTypeinfo;
		this.inProgramMemory = inProgramMemory;
	}
	
	public boolean isSpecialTypeinfo() {
		return isSpecialTypeinfo;
	}
	
	public boolean isInProgramMemory() {
		return inProgramMemory;
	}
	
	public void setInheritedSpecialTypeinfo(GccTypeinfo specialTypeinfo) {
		inheritedSpecialTypeinfo = specialTypeinfo;
	}
		
	
	public GccTypeinfo getInheritedSpecialTypeinfo() {
		return inheritedSpecialTypeinfo;
	}
	
	
	public void setVtableAddress(Address address) {
		vtableAddress = address;
	}
	
	public Address getVtableAddress() {
		return vtableAddress;
	}
	
	public void setMangledNamespaceString(String string) {
		mangledNamespaceString = string;
	}
	
	public String getMangledNamespaceString() {
		return mangledNamespaceString;
	}
	
	public void addBaseTypeinfo(GccTypeinfo baseTypeinfo, int order, boolean isPublic, boolean isVirtual, long offset) {
		baseTypeinfos.add(new BaseTypeinfo(baseTypeinfo, order, isPublic, isVirtual, offset));
	}
	
	public List<BaseTypeinfo> getBaseTypeinfos(){
		return baseTypeinfos;
	}
	
	public List<BaseTypeinfo> getAllBaseTypeinfos(){
		
		Set<BaseTypeinfo> bases = new HashSet<BaseTypeinfo>();
		bases.addAll(getBaseTypeinfos());
		
		List<BaseTypeinfo> basesList = new ArrayList<BaseTypeinfo>(bases);
		for(BaseTypeinfo base : basesList) {
			bases.addAll(base.getBaseTypeinfo().getBaseTypeinfos());
		}
		
		return new ArrayList<BaseTypeinfo>(bases);
		
	}
	
	public int getNumDirectVirtualBases() {
		
		int numVirtualBases = 0;
		for(BaseTypeinfo baseTypeinfo : baseTypeinfos) {
			if(baseTypeinfo.isVirtualBase()) {
				numVirtualBases++;
			}
		}
		return numVirtualBases;
	}
	
	public int getNumAllVirtualBases() {
		int numVirtualBases = 0;
		List<BaseTypeinfo> allBaseTypeinfos = getAllBaseTypeinfos();
		for(BaseTypeinfo baseTypeinfo : allBaseTypeinfos) {
			if(baseTypeinfo.isVirtualBase()) {
				numVirtualBases++;
			}
		}
		return numVirtualBases;
	}

	
	public List<GccTypeinfo> getDirectBases(){
		
		List<GccTypeinfo> bases = new ArrayList<GccTypeinfo> ();
		for(BaseTypeinfo baseTypeinfo : baseTypeinfos) {
			bases.add(baseTypeinfo.getBaseTypeinfo());
		}
		return bases;
	}
	
	public List<GccTypeinfo> getAllBases(){
		
		List<BaseTypeinfo> allBaseTypeinfos = getAllBaseTypeinfos();
		Set<GccTypeinfo> bases = new HashSet<GccTypeinfo>();
		
		for(BaseTypeinfo base : allBaseTypeinfos) {
			bases.add(base.getBaseTypeinfo());
		}
		
		return new ArrayList<GccTypeinfo>(bases);
		
	}
	
	
	public void addInheritanceFlagValue(long flagValue) {
		inheritanceFlagValue = flagValue;
	}
	
	public long getInheritanceFlagValue() {
		return inheritanceFlagValue;
	}
	
	public boolean isClassTypeinfo() {
		if(inheritedSpecialTypeinfo.getNamespace().getName().equals(CLASS_TYPEINFO_NAMESPACE)) {
			return true;
		}
		return false;
	}
	
	public boolean isSiClassTypeinfo() {
		if(inheritedSpecialTypeinfo.getNamespace().getName().equals(SI_CLASS_TYPEINFO_NAMESPACE)) {
			return true;
		}
		return false;
	}
	
	public boolean isVmiClassTypeinfo() {
		if(inheritedSpecialTypeinfo.getNamespace().getName().equals(VMI_CLASS_TYPEINFO_NAMESPACE)) {
			return true;
		}
		return false;
	}

}
