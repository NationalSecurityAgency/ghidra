/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
// A container for records occupying (possibly overlapping)
// intervals.  I.e. a map from a linear ordered domain to
// (multiple) records.
//   recordtype is the type of a record
//      must support
//        constructor(first,last)
//        getFirst()   beginning of range
//        getLast()    end of range (inclusive)
//        getSubsort()
//        initialize() initialization with inittype object
//      must define types
//        linetype
//        subsorttype
//        inittype
//   linetype is the type of elements in the linear domain
//      must support  <,<=,==,!=,  +(integer)  -(integer)
//   subsorttype - overlapping intervals can be subsorted
//      must suport  <
//        null or false initialization produces minimal value
//        true          initialization produces maximal value
//        copy constructor
//   inittype is extra initialization data for the recordtype

#ifndef __RANGEMAP__
#define __RANGEMAP__

#include <set>
#include <list>

template<typename _recordtype>
class rangemap {
  // A class for describing a disjoint partition
public:
  typedef typename _recordtype::linetype linetype;
  typedef typename _recordtype::subsorttype subsorttype;
  typedef typename _recordtype::inittype inittype;
private:
  class AddrRange {
    friend class rangemap<_recordtype>;
    friend class PartIterator;
    mutable linetype first;	// Part of range contained in partition
    linetype last;
    mutable linetype a,b;	// Range occupied by the entire record
    mutable subsorttype subsort;
    AddrRange(linetype l) : subsort(false) { last = l; }
    AddrRange(linetype l,const subsorttype &s) : subsort(s) { last = l; }
  public:
    mutable typename std::list<_recordtype>::iterator value;
    bool operator<(const AddrRange &op2) const {
      if (last != op2.last) return (last < op2.last);
      return (subsort < op2.subsort);
    }
    typename std::list<_recordtype>::iterator getValue(void) const { return value; }
  };
public:
  class PartIterator {		// Iterator over partitions
    typename std::multiset<AddrRange>::const_iterator iter;
  public:
    PartIterator(void) {}
    PartIterator(typename std::multiset<AddrRange>::const_iterator i) { iter=i; }
    _recordtype &operator*(void) { return *(*iter).value; }
    PartIterator &operator++(void) { ++iter; return *this; }
    PartIterator operator++(int i) {
      PartIterator orig(iter); ++iter; return orig; }
    PartIterator &operator--(void) { --iter; return *this; }
    PartIterator operator--(int i) {
      PartIterator orig(iter); --iter; return orig; }
    PartIterator &operator=(const PartIterator &op2) {
      iter = op2.iter; return *this;
    }
    bool operator==(const PartIterator &op2) const {
      return (iter==op2.iter);
    }
    bool operator!=(const PartIterator &op2) const {
      return (iter!=op2.iter);
    }
    typename std::list<_recordtype>::iterator getValueIter(void) const { return (*iter).getValue(); }
  };

  typedef PartIterator const_iterator;

private:
  std::multiset<AddrRange> tree;
  std::list<_recordtype> record;

  void zip(linetype i,typename std::multiset<AddrRange>::iterator iter);
  void unzip(linetype i,typename std::multiset<AddrRange>::iterator iter);
public:
  bool empty(void) const { return record.empty(); }
  void clear(void) { tree.clear(); record.clear(); }
  typename std::list<_recordtype>::const_iterator begin_list(void) const { return record.begin(); }
  typename std::list<_recordtype>::const_iterator end_list(void) const { return record.end(); }
  typename std::list<_recordtype>::iterator begin_list(void) { return record.begin(); }
  typename std::list<_recordtype>::iterator end_list(void) { return record.end(); }

  const_iterator begin(void) const { return PartIterator(tree.begin()); }
  const_iterator end(void) const { return PartIterator(tree.end()); }

  // Find range of intervals intersecting a
  std::pair<const_iterator,const_iterator> find(linetype a) const;

  // Find range of intervals intersecting a, with subsort
  // between (subsort1,subsort2)
  std::pair<const_iterator,const_iterator>
  find(linetype a,const subsorttype &subsort1,const subsorttype &subsort2) const;

  // Find first interval after point, that does not intersect it
  const_iterator find_firstafter(linetype point) const;

  // Find last interval after point, that does not intersect it
  const_iterator find_lastbefore(linetype point) const;

  // Find first interval overlapping given interval
  const_iterator find_overlap(linetype point,linetype end) const;

  typename std::list<_recordtype>::iterator insert(const inittype &data,linetype a,linetype b);
  void erase(typename std::list<_recordtype>::iterator v);
  void erase(const_iterator iter) { erase( iter.getValueIter() ); }
};

template<typename _recordtype>
void rangemap<_recordtype>::zip(linetype i,typename std::multiset<AddrRange>::iterator iter)

{ // Remove the partition boundary occurring right after i
  // This should run in O(k)
  linetype f = (*iter).first;
  while((*iter).last == i)
    tree.erase(iter++);
  i = i+1;
  while((iter!=tree.end())&&((*iter).first==i)) {
    (*iter).first = f;
    ++iter;
  }
}

template<typename _recordtype>
void rangemap<_recordtype>::unzip(linetype i,typename std::multiset<AddrRange>::iterator iter)

{ // Create a new partition boundary right after i
  // This should run in O(k), where k is the number
  // of intervals intersecting the point i
  // iter should be the first interval containing i
  typename std::multiset<AddrRange>::iterator hint = iter;
  if ((*iter).last == i) return; // Can't split size 1 (i.e. split already present)
  linetype f;
  linetype plus1 = i+1;
  while((iter!=tree.end())&&((*iter).first<=i)) {
    f = (*iter).first;
    (*iter).first = plus1;
    typename std::multiset<AddrRange>::iterator newiter;
    newiter = tree.insert(hint,AddrRange(i,(*iter).subsort));
    const AddrRange &newrange( *newiter );
    newrange.first = f;
    newrange.a = (*iter).a;
    newrange.b = (*iter).b;
    newrange.value = (*iter).value;
    ++iter;
  }
}

template<typename _recordtype>
typename std::list<_recordtype>::iterator
rangemap<_recordtype>::insert(const inittype &data,linetype a,linetype b)

{ // Insert a new record into the container at inclusive range [a,b]
  linetype f=a;
  typename std::list<_recordtype>::iterator liter;
  typename std::multiset<AddrRange>::iterator low = tree.lower_bound(AddrRange(f));

  if (low != tree.end()) {
    if ((*low).first < f)	// Check if left boundary refines existing partition
      unzip(f-1,low);		// If so do the refinement
  }

  record.push_front( _recordtype(a,b) );
  record.front().initialize( data );
  liter = record.begin();

  AddrRange addrrange(b,(*liter).getSubsort());
  addrrange.a = a;
  addrrange.b = b;
  addrrange.value = liter;
  typename std::multiset<AddrRange>::iterator spot = tree.lower_bound(addrrange);
  // Where does the new record go in full list, insert it
  record.splice( (spot==tree.end()) ? record.end():(*spot).value,
		 record,liter);

  while((low != tree.end())&&((*low).first<=b)) {
    if (f <= (*low).last) {	// Do we overlap at all
      if (f < (*low).first) {
	// Assume the hint makes this insert an O(1) op
	addrrange.first = f;
	addrrange.last = (*low).first-1;
	tree.insert(low,addrrange);
	f = (*low).first;
      }
      if ((*low).last <= b) {	// Insert as much of interval as we can
	addrrange.first = f;
	addrrange.last = (*low).last;
	tree.insert(low,addrrange);
	if ((*low).last==b) break; // Did we manage to insert it all
	f = (*low).last + 1;
      }
      else if (b < (*low).last) { // We can insert everything left, but must refine
	unzip(b,low);
	break;
      }
    }
    ++low;
  }
  if (f <= b) {
    addrrange.first = f;
    addrrange.last = b;
    tree.insert(addrrange);
  }

  return liter;
}

template<typename _recordtype>
void rangemap<_recordtype>::erase(typename std::list<_recordtype>::iterator v)

{
  linetype a = (*v).getFirst();
  linetype b = (*v).getLast();
  bool leftsew = true;
  bool rightsew = true;
  bool rightoverlap = false;
  bool leftoverlap = false;
  typename std::multiset<AddrRange>::iterator low = tree.lower_bound(AddrRange(a));
  typename std::multiset<AddrRange>::iterator uplow = low;

  linetype aminus1 = a-1;
  while (uplow != tree.begin()) {
    --uplow;
    if ((*uplow).last != aminus1) break;
    if ((*uplow).b == aminus1) {
      leftsew = false;		// Still a split between a-1 and a
      break;
    }
  }
  do {
    if ((*low).value == v)
      tree.erase(low++);
    else {
      if ((*low).a < a)
	leftoverlap = true;	// a splits somebody else
      else if ((*low).a == a)
	leftsew = false;	// Somebody else splits at a (in addition to v)
      if (b < (*low).b)
	rightoverlap = true;	// b splits somebody else
      else if ((*low).b == b)
	rightsew = false;	// Somebody else splits at b (in addition to v)
      low++;
    }
  } while ((low != tree.end())&&((*low).first<=b));
  if (low != tree.end()) {
    if ((*low).a-1 == b)
      rightsew = false;
  }
  if (leftsew&&leftoverlap)
    zip(a-1,tree.lower_bound(AddrRange(a-1)));
  if (rightsew&&rightoverlap)
    zip(b,tree.lower_bound(AddrRange(b)));
  record.erase(v);
}

template<typename _recordtype>
std::pair<typename rangemap<_recordtype>::const_iterator,typename rangemap<_recordtype>::const_iterator>
rangemap<_recordtype>::find(linetype point) const

{ // Get range of intervals which intersect point
  AddrRange addrrange(point);
  typename std::multiset<AddrRange>::const_iterator iter1,iter2;

  iter1 = tree.lower_bound(addrrange);
  // Check for no intersection
  if ((iter1==tree.end())||(point < (*iter1).first))
    return std::pair<PartIterator,PartIterator>(PartIterator(iter1),PartIterator(iter1));

  AddrRange addrend((*iter1).last,subsorttype(true));
  iter2 = tree.upper_bound(addrend);
    
  return std::pair<PartIterator,PartIterator>(PartIterator(iter1),PartIterator(iter2));
}

template<typename _recordtype>
std::pair<typename rangemap<_recordtype>::const_iterator,typename rangemap<_recordtype>::const_iterator>
rangemap<_recordtype>::find(linetype point,const subsorttype &sub1,const subsorttype &sub2) const

{
  AddrRange addrrange(point,sub1);
  typename std::multiset<AddrRange>::const_iterator iter1,iter2;

  iter1 = tree.lower_bound(addrrange);
  if ((iter1==tree.end())||(point < (*iter1).first))
    return std::pair<PartIterator,PartIterator>(PartIterator(iter1),PartIterator(iter1));
  
  AddrRange addrend((*iter1).last,sub2);
  iter2 = tree.upper_bound(addrend);

  return std::pair<PartIterator,PartIterator>(PartIterator(iter1),PartIterator(iter2));
}

template<typename _recordtype>
typename rangemap<_recordtype>::const_iterator
rangemap<_recordtype>::find_lastbefore(linetype point) const

{
  AddrRange addrrange(point);
  typename std::multiset<AddrRange>::const_iterator iter;
  
  // First interval with last >= point
  iter = tree.lower_bound(addrrange);
  if (iter==tree.begin())
    return tree.end();
  --iter;
  return iter;
}

template<typename _recordtype>
typename rangemap<_recordtype>::const_iterator
rangemap<_recordtype>::find_firstafter(linetype point) const

{
  AddrRange addrrange(point,subsorttype(true));
  typename std::multiset<AddrRange>::const_iterator iter;

  iter = tree.upper_bound(addrrange);
  while(iter != tree.end()) {
    if (point < (*iter).a)
      return iter;
    ++iter;
  }
  return tree.end();
}

template<typename _recordtype>
typename rangemap<_recordtype>::const_iterator
rangemap<_recordtype>::find_overlap(linetype point,linetype end) const

{
  AddrRange addrrange(point);
  typename std::multiset<AddrRange>::const_iterator iter;

  // First range where right boundary is equal to or past point
  iter = tree.lower_bound(addrrange);
  if (iter==tree.end()) return iter;
  if (((*iter).first <= point)||((*iter).first<=end))
    return iter;
  return tree.end();
}

#endif
