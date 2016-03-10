/*
 * TaintStructs.h
 *
 *  Created on: 2015年12月17日
 *      Author: wpf
 */

#ifndef TAINTSTRUCTS_H_
#define TAINTSTRUCTS_H_

#endif /* TAINTSTRUCTS_H_ */

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

#include <iostream>
#include <list>


using namespace clang;
using namespace ento;

namespace {

std::string toStr(SVal val) {
	std::string str;
	llvm::raw_string_ostream rso(str);
	val.dumpToStream(rso);
	return rso.str();
}
std::string toStr(SymbolRef ref) {
	std::string str;
	llvm::raw_string_ostream rso(str);
	ref->dumpToStream(rso);
	return rso.str();
}

std::string toStr(const Stmt* s) {
	std::string str;
	llvm::raw_string_ostream rso(str);
	s->dump(rso);
	return rso.str();
}
/*
 *
 struct test{
	mutable  const Expr* origin;
	mutable  const Expr* origin2;
	std::string str;
public:
	test(std::string s){
		str = s;
		//origin = p;
		//origin2 = p;
		std::cout<<"test--->arg1--->: "<<str<<std::endl;
		//if( origin == origin2)
			//std::cout<<"test--->yes "<<std::endl;

	}
};
*/
struct TAINT{
public:
	mutable unsigned int taint;
	mutable SVal origin; /* the memregion, where this taint comes from*/
	mutable unsigned int time; /* the timestamp, when this taint was added*/
	TAINT(unsigned int x, SVal s, unsigned int t){
		taint = x;
		origin = s;
		time = t;
	}

	void showTaint(std::string str="")const{
		std::cout<<str<<"\tTAINT is: "<<taint<<"\torigin is: "<<toStr(origin)<<"\ttime: "<<time<<std::endl;
	}
	void Profile(llvm::FoldingSetNodeID &ID) const {
		ID.AddInteger(taint);
		ID.AddInteger(time);
	}
	bool operator == ( const TAINT &T) const{
		if(taint == T.taint && origin == T.origin && time == T.time)
			return true;
		else
			return false;
	}
	bool operator < ( const TAINT &T) const{
		if(taint < T.taint)
			return true;
		else
			return false;
	}
	bool operator = ( const TAINT &T) const{
		taint = T.taint;
		origin = T.origin;
		time = T.time;
		return true;
	}
	static const  TAINT toConst(TAINT &l) {
		const TAINT ret = l;
		return ret;
	}

};

struct TaintList{

private:
	mutable std::list<TAINT> tlist;
public:

	TaintList() {}

	TaintList(unsigned int x, SVal s, unsigned int t){
		TAINT T(x,s,t);
		tlist.push_back(T);
	}
	TaintList(TAINT &t){
		tlist.push_back(t);
	}
	std::list<TAINT> & getList() const {return tlist;}

	void Add(unsigned int x, SVal s, unsigned int t) const {
		TAINT T(x,s,t);
		tlist.push_back(T);
	}
	void Add(TAINT &t) const {
		TAINT T = t;
		tlist.push_back(T);
	}

	void showTaints(std::string str = "") const{
		int count = 0;
		std::list<TAINT>::iterator i;
		for (i = tlist.begin(); i != tlist.end(); ++i){
			std::cout<<str<<"TaintList: (No."<<count<<") taint is: "<<(*i).taint<<"\torigin is: "<<toStr((*i).origin)<<"\ttime: "<<(*i).time<<std::endl;
			count = count + 1;
		}
	}
	/* return the newest taint that was added before time */
	TAINT* getTaintByTime(unsigned int time)const{
		std::list<TAINT>::iterator i, t;
		t = tlist.begin();
		for (i = tlist.begin(); i != tlist.end(); ++i){
			if ((*i).taint >= (*t).taint && (*i).time <= time){
				t = i;
			}
		}
		//std::cout<<(*t).taint<<" "<<(*t).time<<" "<<toStr((*t).origin)<<std::endl;
		return &(*t);
	}
	bool isEmpty() const{
		return tlist.empty();
	}
	bool contains(TAINT t) const{
		std::list<TAINT>::iterator i;
		for (i = tlist.begin(); i != tlist.end(); ++i){
			if ((*i).taint == t.taint && (*i).origin == t.origin && (*i).time == t.time)
				return true;
		}
		return false;
	}
	// this can be further accelerated.
	bool operator == ( const TaintList &l) const{

		if (tlist.size() != l.tlist.size())
			return false;
		bool diff = false;
		std::list<TAINT>::iterator i;
		std::list<TAINT>::iterator j;

		for (i = tlist.begin(); i != tlist.end(); ++i){
			if(!l.contains(*i))
				return false;
		}
		for (j = l.getList().begin(); j != l.getList().end(); ++j){
			if(!this->contains(*j))
				return false;
		}
		return true;

	}
	void clear() const{
		tlist.clear();
	}
	bool operator = (const TaintList &l) const{
		tlist.clear();
		tlist.assign(l.tlist.begin(),l.tlist.end());
		return true;
	}

	void Profile(llvm::FoldingSetNodeID &ID) const {
		//ID.AddPointer(tlist.begin());
	}
	static const  TaintList* toConst(TaintList * l) {
		const TaintList *ret = l;
		return ret;
	}
	static  TaintList* unConst(const TaintList * l) {
		TaintList *ret;
		ret = (TaintList *)l;
		return ret;
	}

	//may be problem in unique()
	static  TaintList* merge( TaintList* l1,  TaintList* l2) {
		if(!l1 && !l2)
			return NULL;
		else if (!l1)
			return l2;
		else if (!l2)
			return l1;
		else{
			l1->tlist.splice(l1->tlist.end(),l2->tlist);
			l1->tlist.unique();
			return l1;
		}
	}
	void mergeWith(TaintList &l) const{
		std::list<TAINT>::iterator i;
		for (i = l.getList().begin(); i != l.getList().end(); i++){
			if (this->contains(*i))
				continue;
			else
				this->Add(*i);
		}
	}



} ;

typedef struct BRANCH{

	mutable TaintList tlist;
	mutable Expr * cond;
	mutable unsigned int condLoc;
	mutable unsigned int ifStart;
	mutable unsigned int ifEnd;
	mutable bool hasElse;
	mutable unsigned int elseStart;
	mutable unsigned int elseEnd;

	BRANCH(){}
	void Profile(llvm::FoldingSetNodeID &ID) const {
	}
	bool operator == ( const BRANCH &t) const{
		return true;
	}
	bool operator < ( const BRANCH &t) const{
		return true;
	}
	void setCond( Expr* p) const {
		cond = p;
	}
	bool inBranchBody(unsigned int loc) const {
		if (loc >= ifStart && loc <= ifEnd)
			return true;
		if (hasElse){
			if (loc >= elseStart && loc <= elseEnd)
				return true;
		}
		return false;


	}
	TaintList * getTaintListPtrFromBranch() const{
		return &tlist;
	}
	void addTaintsToBranch(TaintList &l) const{
		tlist.mergeWith(l);
	}
	void printBranch(std::string str = "") const{
		std::cout<<">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"<<std::endl;
		std::cout<<"# Taintes are: "<<std::endl;
		if(tlist.isEmpty())
			std::cout<<"no taints\n";
		else
			tlist.showTaints(str);

		std::cout<<"# If range: "<<ifStart<<" - "<<ifEnd<<std::endl;
		if (hasElse)
			std::cout<<"# else range: "<<elseStart<<" - "<<elseEnd<<std::endl;
		else
			std::cout<<"# No else branch.\n";
		std::cout<<"# BranchCondition lo: "<<condLoc<<std::endl;
		//std::cout<<"condition: "<<std::endl;
		//std::cout<<toStr(cond)<<std::endl;

		std::cout<<"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"<<std::endl;
	}

};
typedef struct BranchList{

	mutable std::list<BRANCH> blist;
	BranchList(){}
	void Add(BRANCH &b) const {
		BRANCH B = b;
		blist.push_back(B);
	}
	bool isEmpty() const{
		return blist.empty();
	}
	void showBranchList(std::string str = "") const {
		if (blist.empty())
			std::cout<<str<<"(showBranchList): empty\n";
		else{
			std::list<BRANCH>::iterator i;
			for(i = blist.begin(); i != blist.end(); i++)
				(*i).printBranch(str);
		}

	}
	//add taintList to specific branch
	void addTaintsToSpecBranch(const Expr *expr, TaintList &tls) const{
		std::list<BRANCH>::iterator i;
		for (i = blist.begin(); i != blist.end(); i++){
			if((*i).cond == expr){
				std::cout<<"--->(addTaintsToBranchList): "<<" successed found the branch in branchList by cond expr. \n";
				(*i).tlist.mergeWith(tls);
				return;
			}
		}
		std::cout<<"--->(addTaintsToBranchList): failed, cant find branch\n";
	}
	/*checking if exp in a controlled branch,
	 * if yes return the taintlist, otherwise return null
	 */
	TaintList * getBranchTLbyExprLoc(unsigned int loc)const {
		std::list<BRANCH>::iterator i;
		/*only retuen the last case, which should be the most inner branch,
		 *  cause false negtives for neglecting the outside branch condtions
		 * return list should not be empty
		 */
		std::list<BRANCH>::iterator temp = blist.end();
		for (i = blist.begin(); i != blist.end(); i++){
			if( (*i).inBranchBody(loc) && !((*i).getTaintListPtrFromBranch()->isEmpty())){
				temp = i;
			}
		}
		if(temp != blist.end())
			return (*temp).getTaintListPtrFromBranch();
		return NULL;
	}
	void Profile(llvm::FoldingSetNodeID &ID) const {
	}
	bool operator == ( const BranchList &t) const{
		return true;
	}
	bool operator < ( const BranchList &t) const{
		return true;
	}

};

typedef struct ARG{
	std::string argName;
	std::string funcName;
	bool isPtr;
public:
	ARG() {
		argName = "";
		funcName = "";
		isPtr = false;
	}
	ARG(std::string func, std::string arg, bool type) {
		argName = arg;
		funcName = func;
		isPtr = type;
	}
};


struct ArgsList{
	mutable std::list<ARG> alist;
public:
	ArgsList(){};
	void Add(ARG arg) const {
		alist.push_back(arg);
	}
	bool isEmpty() const{
		if (alist.empty())
			return true;
		else
			return false;
	}
	bool contains(std::string arg, std::string func) const{
		std::list<ARG>::iterator i;
		for (i = alist.begin(); i != alist.end(); ++i)
		{
			if ((*i).argName == arg && (*i).funcName == func)
				return true;
		}
		return false;
	}
	void showArgs() const{
		std::list<ARG>::iterator i;

		for (i = alist.begin(); i != alist.end(); i++){
			std::cout<<"[show args]"<<"func name: "<<(*i).funcName<<"\targName:"<<(*i).argName<<"\targType:"<<(*i).isPtr<<std::endl;
		}

	}


};
struct FuncTable{
	mutable std::map<unsigned int, std::string> mapTable;
	mutable std::map<unsigned int, std::string>::iterator it;
	FuncTable(){}
	void insertItem(unsigned int loc, std::string name) const{
		mapTable.insert( std::pair<unsigned int, std::string>(loc, name) );
		//mapTable.insert( make_pair(loc, name) );
		//mapTable.insert( std::map<unsigned int, std::string>::value_type(loc, name));

		//mapTable.insert(loc, name);
		//mapTable[loc] = name;
	}
	std::string getNameByLoc(unsigned int loc) const {
		it = mapTable.find(loc);
		if(it != mapTable.end() ){
			//fout<<"[find  func] func:"<<func<<std::endl;
			return it->second;
		}
		else
			return "";
	}
	void showLoc(unsigned int loc)const{

		std::string name = this->getNameByLoc(loc);
		std::cout<<"---> loc: "<<loc<<"\tname"<<name<<std::endl;
	}
};
}// namespace end
