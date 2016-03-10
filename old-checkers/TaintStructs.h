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

std::string toStr(const Stmt* s) {
	std::string str;
	llvm::raw_string_ostream rso(str);
	s->dump(rso);
	return rso.str();
}


typedef struct STATE_struct{
private:
	std::string name;
	SVal val;
	unsigned int count;
	unsigned int taint;
	bool isLoc;
	bool isPtr;
	//bool isBase;

public:
	STATE_struct(std::string n, SVal v, unsigned int c, int t = 0, bool l = false, bool p = false){
		name = n;
		val = v;
		count = c;
		taint = t;
		isLoc = l;
		isPtr = p;
	}

	unsigned int getCount() const{
		return count;
	}
	unsigned int getTaint() const{
		return taint;
	}
	bool isLocal() const{
		return isLoc;
	}
	bool isPointer() const{
		return isPtr;
	}
	STATE_struct getAsIncre() const { return STATE_struct(name, val, count+1, taint, isLoc, isPtr);}

	void showState(std::string str = "") const {
		std::cout<<str<<" name: "<<name<<"\tval: "<<toStr(val)<<"\tcount: "<<count<<"\ttaint: "<<taint
				<<"\tisLoc: "<<isLoc<<"\tisPtr: "<<isPtr<<std::endl;
	}

	bool operator == ( const STATE_struct &T) const{
		if (count == T.count && name == T.name && val == T.val
				&& taint == T.taint && isLoc == T.isLoc && isPtr == T.isPtr)
			return true;
		else
			return false;
	}
	void Profile(llvm::FoldingSetNodeID &ID) const {
		ID.AddInteger(count);
		ID.AddInteger(taint);
		ID.AddBoolean(isLoc);
		ID.AddBoolean(isPtr);

	}

}STATE;

typedef struct TAINT_struct{
public:
	mutable unsigned int tag;
	mutable SVal origin;
	mutable unsigned int time;
	TAINT_struct(unsigned int x, SVal s, unsigned int t){
		tag = x;
		origin = s;
		time = t;
	}
	TAINT_struct(){
		//tag = 0;
		//time = 0;
	}
	void showTaint(std::string str="")const{
		std::cout<<str<<"\tTAINT tag is: "<<tag<<"\torigin is: "<<toStr(origin)<<"\ttime: "<<time<<std::endl;
	}
	void Profile(llvm::FoldingSetNodeID &ID) const {
		ID.AddInteger(tag);
	}
	bool operator == ( const TAINT_struct &T) const{
		if(tag == T.tag && origin == T.origin && time == T.time)
			return true;
		else
			return false;
	}
	bool operator < ( const TAINT_struct &T) const{
		if(tag < T.tag)
			return true;
		else
			return false;
	}
	bool operator = ( const TAINT_struct &T) const{
		tag = T.tag;
		origin = T.origin;
		time = T.time;
		return true;
	}
	static const  TAINT_struct toConst(TAINT_struct &l) {
		const TAINT_struct ret = l;
		return ret;
	}

} TAINT;

typedef struct TaintList_struct{


private:
	mutable std::list<TAINT> tlist;
public:

	TaintList_struct() {}

	TaintList_struct(unsigned int x, SVal s, unsigned int t){
		TAINT T(x,s,t);
		tlist.push_back(T);
	}
	TaintList_struct(TAINT &t){
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
			std::cout<<"#"<<str<<" # TaintList-showTaints#:(No."<<count<<") tag is: "<<(*i).tag<<"\torigin is: "<<toStr((*i).origin)<<"\ttime: "<<(*i).time<<std::endl;
			count = count + 1;
		}
	}
	TAINT* getTaintByTime(unsigned int time)const{
		std::list<TAINT>::iterator i, t;
		t = tlist.begin();
		for (i = tlist.begin(); i != tlist.end(); ++i){
			if ((*i).tag >= (*t).tag && (*i).time <= time){
				t = i;
			}
		}
		//std::cout<<(*t).tag<<" "<<(*t).time<<" "<<toStr((*t).origin)<<std::endl;
		return &(*t);
	}
	bool isEmpty() const{
		return tlist.empty();
	}
	bool contains(TAINT t) const{
		std::list<TAINT>::iterator i;
		for (i = tlist.begin(); i != tlist.end(); ++i){
			if ((*i).tag == t.tag && (*i).origin == t.origin && (*i).time == t.time)
				return true;
		}
		return false;
	}
	// this can be further accelerated.
	bool operator == ( const TaintList_struct &l) const{

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
	bool operator = (const TaintList_struct &l) const{
		tlist.clear();
		tlist.assign(l.tlist.begin(),l.tlist.end());
		return true;
	}

	void Profile(llvm::FoldingSetNodeID &ID) const {
		//ID.AddPointer(tlist.begin());
	}
	static const  TaintList_struct* toConst(TaintList_struct * l) {
		const TaintList_struct *ret = l;
		return ret;
	}
	static  TaintList_struct* unConst(const TaintList_struct * l) {
		TaintList_struct *ret;
		ret = (TaintList_struct *)l;
		return ret;
	}

	//may be problem in unique()
	static  TaintList_struct* merge( TaintList_struct* l1,  TaintList_struct* l2) {
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
	void mergeWith(TaintList_struct &l) const{
		std::list<TAINT>::iterator i;
		for (i = l.getList().begin(); i != l.getList().end(); i++){
			if (this->contains(*i))
				continue;
			else
				this->Add(*i);
		}
	}



} TaintList;

typedef struct Branch_struct{

	mutable TaintList tlist;
	mutable Expr * cond;
	mutable unsigned int condLoc;
	mutable unsigned int ifStart;
	mutable unsigned int ifEnd;
	mutable bool hasElse;
	mutable unsigned int elseStart;
	mutable unsigned int elseEnd;

	Branch_struct(){}
	void Profile(llvm::FoldingSetNodeID &ID) const {
	}
	bool operator == ( const Branch_struct &t) const{
		return true;
	}
	bool operator < ( const Branch_struct &t) const{
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
	TaintList * getListPtr() const{
		return &tlist;
	}
	void addTaintsToBranch(TaintList &l) const{
		tlist.mergeWith(l);
	}
	void printBranch(std::string str) const{
		std::cout<<str<<">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"<<std::endl;
		std::cout<<"#printBranch# taintes are: "<<std::endl;
		if(tlist.isEmpty())
			std::cout<<"no taints\n";
		else
			tlist.showTaints(str);
		std::cout<<"#printBranch# if range: "<<ifStart<<" - "<<ifEnd<<std::endl;
		if (hasElse)
			std::cout<<"#printBranch# else range: "<<elseStart<<" - "<<elseEnd<<std::endl;
		else
			std::cout<<"#printBranch# no else.\n";
		std::cout<<"#printBranch# condition location: "<<condLoc<<std::endl;
		std::cout<<"#printBranch# condition: "<<std::endl;
		std::cout<<toStr(cond)<<std::endl;
		std::cout<<str<<"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"<<std::endl;
	}

} BRANCH;
typedef struct BranchList_struct{

	mutable std::list<BRANCH> blist;
	BranchList_struct(){}
	void Add(BRANCH &b) const {
		BRANCH B = b;
		blist.push_back(B);
	}
	bool isEmpty() const{
		return blist.empty();
	}
	void showBranchList(std::string str = "") const {
		if (blist.empty())
			std::cout<<"(showBranchList): empty\n";
		else{
			std::list<BRANCH>::iterator i;
			for(i = blist.begin(); i != blist.end(); i++)
				(*i).printBranch(str);
		}

	}
	//add taintList to specific branch
	void addTaintsToSpecBranch(const Expr *exp, TaintList &tls) const{
		std::list<BRANCH>::iterator i;
		//std::cout<<"(BranchList)->addTaintsT"<<std::endl;
		for (i = blist.begin(); i != blist.end(); i++){
			if((*i).cond == exp){
				std::cout<<"(BranchList)->addTaintsToBranchList: "<<" find the branch in branchList by cond. \n";
				(*i).tlist.mergeWith(tls);
			}
			else
				std::cout<<"(BranchList)->addTaintsToBranchList:miss\n";
		}
	}
	//if exp in a controlled branch, return the taintlist, otherwise return null
	TaintList * exprInTaintedBranch(const Expr* erg, unsigned int loc)const {
		std::list<BRANCH>::iterator i;
		// only retuen the first case, cause false negtives
		for (i = blist.begin(); i != blist.end(); i++){
			if( (*i).inBranchBody(loc))
				return (*i).getListPtr();
		}

	}
	void Profile(llvm::FoldingSetNodeID &ID) const {
	}
	bool operator == ( const BranchList_struct &t) const{
		return true;
	}
	bool operator < ( const BranchList_struct &t) const{
		return true;
	}

} BranchList;

typedef struct Arg_struct{
	std::string argName;
	std::string funcName;
	std::string argType;
public:
	Arg_struct() {
		argName = "";
		funcName = "";
		argType = "";
	}
	Arg_struct(std::string func, std::string arg, std::string type) {
		argName = arg;
		funcName = func;
		argType = type;
	}
} ARG;


typedef struct ArgsList_struct{
	mutable std::list<ARG> alist;
public:
	ArgsList_struct(){};
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
			std::cout<<"[show args]"<<"func name: "<<(*i).funcName<<"\targName:"<<(*i).argName<<"\targType:"<<(*i).argType<<std::endl;
		}

	}


} ArgsList;




}// namespace end
