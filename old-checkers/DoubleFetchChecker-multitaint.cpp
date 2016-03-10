/*
 * DoubleFetchChecker.cpp
 *
 *  Created on: 2015年12月14日
 *      Author: wpf
 *
 * This is the implementation file of double-fetch checker, which should be put in the
 * directory lib/StaticAnalyzer/Checkers
 *
 */

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/StmtVisitor.h"


#include <iostream>
#include <list>

using namespace clang;
using namespace ento;
namespace {


//typedef std::list<unsigned int> TaintList;
typedef struct TAINT_struct{
public:
	mutable unsigned int tag;
	mutable SVal origin;
	TAINT_struct(unsigned int x, SVal s){
		tag = x;
		origin = s;
	}
	TAINT_struct(){}
	void Profile(llvm::FoldingSetNodeID &ID) const {
		ID.AddInteger(tag);
	}
	bool operator == ( const TAINT_struct &t) const{
		if(tag == t.tag && origin == t.origin)
			return true;
		else
			return false;
	}
	bool operator < ( const TAINT_struct &t) const{
		if(tag < t.tag)
			return true;
		else
			return false;
	}
	bool operator = ( const TAINT_struct &t) const{
		tag = t.tag;
		origin = t.origin;
		return true;
	}
	static const  TAINT_struct toConst(TAINT_struct &l) {
		const TAINT_struct ret = l;
		return ret;
	}

}TAINT;

typedef struct TaintList_struct{

private:

	mutable bool empty = true; // determine whether it is an empty list
public:
	mutable std::list<TAINT> tlist;
	TaintList_struct() {}

	TaintList_struct(unsigned int t, SVal s){
		TAINT T(t,s);
		tlist.push_back(T);
		empty = false;
	}
	std::list<TAINT> getList() const {return tlist;}

	std::string toStr(SVal val) const{
		std::string str;
		llvm::raw_string_ostream rso(str);
		val.dumpToStream(rso);
		return rso.str();
	}

	void Add(unsigned int t, SVal s) const {
		TAINT T(t,s);
		tlist.push_back(T);
		empty = false;
	}
	void Add(TAINT t) const {
		TAINT T = t;
		tlist.push_back(T);
		empty = false;
	}

	void showTaints(std::string str = "") const{
		int count = 0;
		std::list<TAINT>::iterator i;
		for (i = tlist.begin(); i != tlist.end(); ++i){
			std::cout<<"#"<<str<<" # TaintList-showTaints#:(No."<<count<<") tag is: "<<(*i).tag<<"\torigin is: "<<toStr((*i).origin)<<std::endl;
			count = count + 1;
		}
	}
	bool isEmpty() const{
		return empty;
	}
	bool contains(TAINT t) const{
		std::list<TAINT>::iterator i;
		for (i = tlist.begin(); i != tlist.end(); ++i){
			if ((*i).tag == t.tag && (*i).origin == t.origin)
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

	bool operator = (const TaintList_struct l) const{
		tlist.clear();
		empty = l.empty;
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
} TaintList;


class MyASTVisitor: public RecursiveASTVisitor<MyASTVisitor> {

public:
	explicit MyASTVisitor(){}

	bool VisitStmt(Stmt* I){
		if(isa<CompoundStmt>(I) )
			printf("is CompoundStmt\n");
		if(isa<IfStmt>(I))
			printf("is IfStmt\n");
		printf("visit stmt\n");
		return true;
	};
	bool VisitDecl(Decl* D){
		printf("visit decl\n");
		return true;
	}
	bool VisitFunctionDecl(FunctionDecl *f) {
		std::cout<<"visit funcdecl:"<<f->getNameAsString()<<std::endl;

		return true;
	}
    //bool VisitIfStmt(const IfStmt *I);
     //void VisitCompoundStmt (CompoundStmt *S);
};


//bool MyASTVisitor::VisitStmt(Stmt *s)

/*
bool MyASTVisitor::VisitIfStmt(const Stmt *s) {
	//const Stmt *Stmt1 = I->getThen();
	//const Stmt *Stmt2 = I->getElse();

}
*/

class DoubleFetchChecker : public Checker<check::Location,
										check::Bind,
										check::PreCall,
										check::PostCall,
										check::PostStmt<Expr>,
										check::PreStmt<Expr>,
										check::PostStmt<BlockExpr>,
										check::PreStmt<CallExpr>,
										check::PostStmt<CallExpr>,
										check::BranchCondition,
										check::EndFunction,
										check::ASTDecl<FunctionDecl>,
										check::ASTCodeBody> {
private:
	std::unique_ptr<BugType> DoubleFetchType;

	mutable int MaxTag = -1;// -1 indicates no tainting
	mutable std::string funcName ="";
	mutable std::string funcArg ="";
	mutable std::string funcRet = "";
	mutable const FunctionDecl* funcDecl;

public:
	DoubleFetchChecker();
	void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
	//void checkPreStmt(const BlockExpr *BE, CheckerContext &Ctx) const;
	void checkPostStmt(const BlockExpr *BE, CheckerContext &Ctx) const;

	void checkPreCall(const CallEvent &Call,CheckerContext &Ctx) const;
	void checkPostCall(const CallEvent &Call,CheckerContext &Ctx) const;

	void checkPreStmt(const CallExpr *CE, CheckerContext &Ctx) const;
	void checkPostStmt(const CallExpr *CE, CheckerContext &Ctx) const;

	void checkPreStmt(const Expr *E, CheckerContext &Ctx) const;
	void checkPostStmt(const Expr *E, CheckerContext &Ctx) const;

	void checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const;
	void checkLocation(SVal loc, bool isLoad, const Stmt* LoadS, CheckerContext &Ctx) const;
	void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;

	void checkEndFunction(CheckerContext &Ctx) const;


	void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
	                        BugReporter &BR) const {
	    MyASTVisitor Visitor;
	    Visitor.TraverseDecl(const_cast<Decl *>(D));
	    //Visitor.TraverseStmt();
	    //Visitor.Visit(D->getBody());
	  }


	// my own functions
	void reportDoubleFetch(CheckerContext &Ctx) const;
	std::string toStr(const SVal &val) const;
	std::string toStr(const Stmt* s) const;
	SymbolRef getSymbolRef(SVal val) const;

	unsigned int getNewTag() const;
	void showTaintTags(ProgramStateRef state, SVal val) const;
	unsigned int getCurTag(ProgramStateRef state, SVal val) const;

	bool diffTaintInBranch(ProgramStateRef state, SVal arg) const;

	bool beTainted(ProgramStateRef state, SVal val) const;
	ProgramStateRef addNewTaint(ProgramStateRef state, SVal val) const;
	ProgramStateRef passTaints(ProgramStateRef state, SVal src, SVal dst) const;
	ProgramStateRef passTaintsToBranch(ProgramStateRef state, SVal src) const;
	ProgramStateRef addTaints(ProgramStateRef state, SymbolRef Sym, TaintList tl) const;
	ProgramStateRef addTaintToBranch(ProgramStateRef state, TAINT t)const;

	bool ifTainted(ProgramStateRef state, SymbolRef Sym) const;
	bool ifTainted(ProgramStateRef state, const Stmt *S, const LocationContext *LCtx) const;
	bool ifTainted(ProgramStateRef state, SVal V) const;
	bool ifTainted(ProgramStateRef state, const MemRegion *Reg) const;

	 TaintList* getTaintList(ProgramStateRef state, SymbolRef Sym) const;
	 TaintList* getTaintList(ProgramStateRef state, const Stmt *S, const LocationContext *LCtx) const;
	 TaintList* getTaintList(ProgramStateRef state, SVal V) const;
	 TaintList* getTaintList(ProgramStateRef state, const MemRegion *Reg) const;

}; //class end
}// namespace end

//REGISTER_TRAIT_WITH_PROGRAMSTATE(TaintTag, unsigned)
//REGISTER_LIST_WITH_PROGRAMSTATE	(AccessList, SVal)

REGISTER_MAP_WITH_PROGRAMSTATE(TaintsMap, SymbolRef, TaintList)
REGISTER_SET_WITH_PROGRAMSTATE(BranchTaintSet, TAINT)

DoubleFetchChecker::DoubleFetchChecker() {
	// Initialize the bug types.
	DoubleFetchType.reset(new BugType(this, "Double Fetch", "Unix kernel TOCTOU Error"));
	// Sinks are higher importance bugs as well as calls to assert() or exit(0).
	//DoubleFetchType->setSuppressOnSink(true);
}

void DoubleFetchChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	funcName = D->getNameAsString();
	funcRet = D->getReturnType().getAsString();
	funcDecl = D;
	if(D->getNumParams() > 0)
	  funcArg = D->parameters()[0]->getQualifiedNameAsString();

	Stmt* body = D->getBody();

/*
	const ParmVarDecl * pdecl =	D->getParamDecl(0);
	const Expr * argexpr = pdecl->getDefaultArg();

	if (argexpr->isLValue())
		std::cout<<"[checkASTDecl<FunctionDecl>],\t is lvalue:"<<funcName<<std::endl;
	else if(argexpr->isRValue())
		std::cout<<"[checkASTDecl<FunctionDecl>],\t is rvalue:"<<funcName<<std::endl;
*/
	std::cout<<"[checkASTDecl<FunctionDecl>],\t funcname is:"<<funcName<<std::endl;
	std::cout<<"[checkASTDecl<FunctionDecl>],\t retType is:"<<funcRet<<std::endl;
	std::cout<<"[checkASTDecl<FunctionDecl>],\t arg0 is:"<<funcArg<<std::endl;
//llvm::errs() << "Switch Statement found.\n";
}



void DoubleFetchChecker::checkPostStmt(const BlockExpr *BE, CheckerContext &Ctx) const{

	const BlockDecl* bd = BE->getBlockDecl();
	std::cout<<"[checkPostStmt<BlockExpr>]"<<"xxxxxxxxxxxxxxxxxxxx"<<std::endl;
}

void DoubleFetchChecker::checkPreStmt(const Expr* E, CheckerContext &Ctx) const {
	ProgramStateRef state = Ctx.getState();
	SVal ExpVal = state->getSVal(E, Ctx.getLocationContext());

	if (isa<BlockExpr>(E))
		std::cout<<"xxxsssssssssssssssssssssssssssssssssssssssss"<<std::endl;

	//std::cout<<"[checkPreStmt<Expr>] "<<toStr(E)<<std::endl;
/*
	if(!isUntainted(state,ExpVal)){
		std::cout<<"[checkPreStmt<Expr>]"<<"\ttainted, \t ";
		showTaintTags(state, ExpVal);
	}
	 else
		std::cout<<"[checkPreStmt<Expr>] not tainted"<<"\t Expr Sval is:"<<toStr(ExpVal)<<std::endl;
*/


}
void DoubleFetchChecker::checkPostStmt(const Expr* E, CheckerContext &Ctx) const {
	ProgramStateRef state = Ctx.getState();
	SVal ExpVal = state->getSVal(E, Ctx.getLocationContext());
	if (isa<BlockExpr>(E))
		std::cout<<"sssssssssssssssssssssssssssssssssssssssss"<<std::endl;
	//std::cout<<"[checkPostStmt<Expr>] "<<toStr(E)<<std::endl;
	/*
	if(!isUntainted(state,ExpVal)){
		std::cout<<"[checkPostStmt<Expr>]"<<"\ttainted, \t ";
		showTaintTags(state, ExpVal);
	}
	 else
		std::cout<<"[checkPostStmt<Expr>] not tainted"<<"\t Expr Sval is:"<<toStr(ExpVal)<<std::endl;
*/

}

void DoubleFetchChecker::checkPreStmt(const CallExpr *CE, CheckerContext &Ctx) const{
	ProgramStateRef state = Ctx.getState();
	const FunctionDecl *FDecl = Ctx.getCalleeDecl(CE);
	StringRef funcName = Ctx.getCalleeName(FDecl);
	//std::cout<<"[checkPreStmt<CallExpr>] func name is:"<<funcName.<<std::endl;
	printf("[checkPreStmt<CallExpr>] func name is:%s\n",funcName);
}

void DoubleFetchChecker::checkPostStmt(const CallExpr *CE, CheckerContext &Ctx) const{
	ProgramStateRef state = Ctx.getState();
	const FunctionDecl *FDecl = Ctx.getCalleeDecl(CE);
	StringRef funcName = Ctx.getCalleeName(FDecl);
	//std::cout<<"[checkPostStmt<CallExpr>] func name is:"<<funcName<<std::endl;
	printf("[checkPostStmt<CallExpr>] func name is:%s\n",funcName);

}



void DoubleFetchChecker::checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();
	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		printf(" R return \n");
		return;
	}

	if(ifTainted(state,val)){
		std::cout<<"[checkbind()][tainted]"<<"\tlocation is: "<<toStr(loc)<<"\tbind value is: "<<toStr(val)<<std::endl;
		showTaintTags(state, val);
	}
	else
		std::cout<<"[checkbind()][not tainted]"<<"\tlocation is: "<<toStr(loc)<<"\tbind value is: "<<toStr(val)<<std::endl;


}



void DoubleFetchChecker::checkLocation( SVal loc, bool isLoad, const Stmt* LoadS,
	CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();
	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		printf(" R return \n");
		return;
	}

	SVal val= state->getSVal(mrptr);
	std::cout<<"[checkLocation()]"<<"\tlocation is: "<<toStr(loc)<<"\taccess value is: "<<toStr(val);



	if(ifTainted(state, val) && isLoad)
		std::cout<<" \ttainted"<<std::endl;
	if(!ifTainted(state, val) && isLoad)
		std::cout<<" \tuntainted"<<std::endl;


	//any access to the user passed arg, or subregion of that arg shouled be added a new taint.
	std::string locStr = mrptr->getString();
	if (locStr == funcArg){
		std::cout<<"[checkLocation()]"<<" ==== find function decl Arg: "<<locStr<<std::endl;

		state = addNewTaint(state, val);
		Ctx.addTransition(state);
	}


/*
	DefinedOrUnknownSVal location = loc.castAs<DefinedOrUnknownSVal>();
	ProgramStateRef notNullState, nullState;
	std::tie(notNullState, nullState) = state->assume(location);

	// Check for null dereferences.
	if (!location.getAs<Loc>()){
		printf("Null dereferences\n");
		return;
	}

	// The explicit NULL case.
	if (nullState) {
	    if (!notNullState) {
	    	printf("explicit NULL case\n");
	    	return;
	    }
	 }
*/
}

void DoubleFetchChecker::checkBranchCondition(const Stmt *Condition,
	CheckerContext &Ctx) const {

	ProgramStateRef state = Ctx.getState();

	/*
	 SVal condiSval = state->getSVal(Condition, Ctx.getLocationContext());
	if (condiSval.isUnknownOrUndef())
		printf("condiSval isUnknownOrUndef\n");

	*/

	//ASTContext AST = Ctx.getASTContext();
	 //AnalysisManager &AM = Ctx.getAnalysisManager();

	//CFG *cfg = AM.getCFG(funcDecl);
	//cfg->dump();
	//CFGBlock entry = cfg->getEntry();
	//entry.dump();
	//CFGBlock exit = cfg->getExit();
	//entry.dump();

	//state->dump();
	//state->dumpTaint();

	SVal Val;
	if (const BinaryOperator *B = dyn_cast<BinaryOperator>(Condition)) {
	    if (B->isComparisonOp()) {
	    	Expr * rp = B->getRHS();
	    	Expr * lp = B->getLHS();

	    	SVal rsval = state->getSVal(rp, Ctx.getLocationContext());
	    	SVal lsval = state->getSVal(lp, Ctx.getLocationContext());

	    	if(ifTainted(state,rsval)){
	    		std::cout<<"[checkBranch]"<<"\ttainted, binary rsval is:  "<<toStr(rsval)<<std::endl;
	    		showTaintTags(state, rsval);
	    		state = passTaintsToBranch(state, rsval);
	    		Ctx.addTransition(state);
	    	}
	    	 else
	    		std::cout<<"[checkBranch] not tainted"<<"\tbinary rsval is: "<<toStr(rsval)<<std::endl;

	    	if(ifTainted(state,lsval)){
				std::cout<<"[checkBranch]"<<"\ttainted, binary lsval is:  "<<toStr(lsval)<<std::endl;
				showTaintTags(state, lsval);
				state = passTaintsToBranch(state, lsval);
				Ctx.addTransition(state);
			}
			 else
				std::cout<<"[checkBranch] not tainted"<<"\tbinary lsval is: "<<toStr(lsval)<<std::endl;

	    }
	  }
	else if (const UnaryOperator *U = dyn_cast<UnaryOperator>(Condition)){
		Expr* sp = U->getSubExpr();
		SVal ssval = state->getSVal(sp, Ctx.getLocationContext());

		if(ifTainted(state,ssval)){
			std::cout<<"[checkBranch]"<<"\ttainted, unary ssval is: ";
			showTaintTags(state, ssval);
			state = passTaintsToBranch(state, ssval);
			Ctx.addTransition(state);
		}
		 else
			std::cout<<"[checkBranch] not tainted"<<"\tunary ssval is: "<<toStr(ssval)<<std::endl;

	}

	// two branches
	//ProgramStateRef trueState, falseState;
	//std::tie(trueState, falseState) = state->assume(dv);


}


void DoubleFetchChecker::checkPreCall(const CallEvent &Call,CheckerContext &Ctx) const {
	const IdentifierInfo *ID = Call.getCalleeIdentifier();
	ProgramStateRef state = Ctx.getState();
	if (ID == NULL) {
		return;
	}
	std::cout<<"[checkPreCall]-----call function:"<<ID->getName().str()<<std::endl;


	if(ID->getName() == "kernel_func") {
		ProgramStateRef state = Ctx.getState();
		SVal arg = Call.getArgSVal(0);
		const MemRegion* mr = arg.getAsRegion();
		/*
		state = state->add<TaintRegionMap>(mr);
		Ctx.addTransition(state);

		SVal val = state->getSVal(mr);
		ProgramStateRef newstate = addTaintToSymExpr(state, val);
		if(newstate){
			Ctx.addTransition(newstate);
			std::cout<<"[checkPreCall] arg add taint finish: "<<toStr(arg)<<std::endl;
		}
		else
			std::cout<<"[checkPreCall] arg add taint failed: "<<toStr(arg)<<std::endl;
*/
	}


}
void DoubleFetchChecker::checkPostCall(const CallEvent &Call,CheckerContext &Ctx) const {
	const IdentifierInfo *ID = Call.getCalleeIdentifier();
	std::cout<<"[checkPostCall]------call function:"<<ID->getName().str()<<std::endl;

	ProgramStateRef state = Ctx.getState();
	if(ID == NULL) {
		return;
	}

	if (ID->getName() == "malloc") {
		SVal arg = Call.getArgSVal(0);
		SVal ret = Call.getReturnValue();
		if (ifTainted(state, arg)){
			std::cout<<"[checkPostCall] arg of malloc is tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
			//pass current taint tag to return value
			ProgramStateRef newstate = passTaints(state, arg, ret);
			if (newstate!=state && newstate != NULL){
				Ctx.addTransition(newstate);
				std::cout<<"[checkPostCall][add ret Taint finish] ret is "<<toStr(ret)<<std::endl;
				showTaintTags(newstate, ret);
			}
			else
				std::cout<<"[checkPostCall][add ret Taint failed] ret is "<<toStr(ret)<<std::endl;
		}

		else{
			std::cout<<"[checkPostCall] arg of malloc not tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
		}
	}


	if (ID->getName() == "__builtin___memcpy_chk") {
		SVal Arg0 = Call.getArgSVal(0);
		SVal Arg1 = Call.getArgSVal(1);
		SVal Arg2 = Call.getArgSVal(2);
		if(ifTainted(state,Arg0)){
			std::cout<<"[checkPreCall]"<<"\tArg0, tainted, \t "<<std::endl;
			showTaintTags(state, Arg0);
		}
		else
			std::cout<<"[checkPreCall]"<<"\tArg0, not tainted, \t "<<std::endl;

		if(ifTainted(state,Arg1)){
			std::cout<<"[checkPreCall]"<<"\tArg1, tainted, \t "<<std::endl;
			showTaintTags(state, Arg1);
		}
		else
			std::cout<<"[checkPreCall]"<<"\tArg1, not tainted, \t "<<std::endl;

		if(ifTainted(state,Arg2)){
			std::cout<<"[checkPreCall]"<<"\tArg2, tainted, \t "<<std::endl;
			showTaintTags(state, Arg2);
		}
		else
			std::cout<<"[checkPreCall]"<<"\tArg2, not tainted, \t "<<std::endl;

		if(diffTaintInBranch(state,Arg0) || diffTaintInBranch(state,Arg1) || diffTaintInBranch(state,Arg2)){

				printf("### Found DF!!#####\n");
				this->reportDoubleFetch(Ctx);

		}


	}


}
void DoubleFetchChecker::reportDoubleFetch(CheckerContext &Ctx) const {
	// We reached a bug, stop exploring the path here by generating a sink.
	ExplodedNode *ErrNode = Ctx.generateErrorNode(Ctx.getState());
	// If we've already reached this node on another path, return.
	if (!ErrNode)
		return;

	// Generate the report.
	auto R = llvm::make_unique<BugReport>(*DoubleFetchType,
			"Double-Fetch", ErrNode);
	//R->addRange(Call.getSourceRange());
	Ctx.emitReport(std::move(R));
}

void DoubleFetchChecker::checkEndFunction(CheckerContext &Ctx) const {
	std::cout<<"[checkEndFunction]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;
}

//any access to the user passed arg, or subregion of that arg shouled be added a new taint.
ProgramStateRef DoubleFetchChecker::addNewTaint(ProgramStateRef state, SVal val) const {
	SymbolRef  SE = this->getSymbolRef(val);
	if (!SE){
		std::cout<<"(addNewTaint) getSymbolRef failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	else{
		unsigned int newtag = getNewTag();
		MaxTag = newtag;
		ProgramStateRef newstate;
		const TaintList *tlp = state->get<TaintsMap>(SE);
		// if tainted before, just add new tag to the taintList
		if (tlp){
			tlp->Add(newtag, val);
			newstate = addTaints(state, SE, *tlp);
		}
		//not tainted before, add a new taintList to the symbol
		else{
			TaintList tl(newtag, val);
			newstate = addTaints(state, SE, tl);
		}

		std::cout<<"(addNewTaint) add new taint finished!"<<"\tval is:"<<toStr(val)<<"\t tag is:"<<newtag<<std::endl;
		if (newstate->get<TaintsMap>(SE)){
			const TaintList *s = newstate->get<TaintsMap>(SE);
			s->showTaints("add new taint succedd");
		}

		return newstate;
	}
}
ProgramStateRef DoubleFetchChecker::passTaintsToBranch(ProgramStateRef state, SVal src) const {


	TaintList *tlps = this->getTaintList(state,src);
	if (!tlps){
		std::cout<<"(passTaintToBranch), no original taints return state"<<std::endl;
		return state;
	}
	tlps->showTaints("pass taint to branch");

	std::list<TAINT>::iterator i;

	for ( i=tlps->tlist.begin(); i!=tlps->tlist.end(); i++ ) {
		std::cout<<"(passTaintsToBranch,for)\t tag: "<<(*i).tag<<"\t origin: "<<this->toStr((*i).origin)<<std::endl;

		if (state->contains<BranchTaintSet>(*i)){
			continue;
		}
		else{
			//std::cout<<"bbbbb"<<(*i).tag<<"   "<<this->toStr((*i).origin)<<std::endl;
			state = state->add<BranchTaintSet>(*i);
		}

	}
	return state;
}

SymbolRef DoubleFetchChecker::getSymbolRef(SVal val) const {
	if(val.isConstant()){
		std::cout<<"(getSymbolRef) val failed! IsConstant."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	if(val.isUnknownOrUndef()){
		std::cout<<"(getSymbolRef) val failed! IsUnknownOrUndef."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	const SymExpr * SE = val.getAsSymExpr();
	if (!SE){
		std::cout<<"(getSymbolRef) getAsSymExpr failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	else
		return SE;

	const MemRegion *Reg = val.getAsRegion();
	if(!Reg){
		std::cout<<"(getSymbolRef) getAsRegion failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	else{
		if (const SymbolicRegion *SR = dyn_cast_or_null<SymbolicRegion>(Reg)){
			std::cout<<"(getSymbolRef) getAsRegion succeed."<<std::endl;
			return SR->getSymbol();
		}

	}


}
ProgramStateRef DoubleFetchChecker::passTaints(ProgramStateRef state, SVal src, SVal dst) const {

	SymbolRef  SEs = this->getSymbolRef(src) ;
	if (!SEs){
		std::cout<<"(passTaints) getSymbolRef failed!"<<"\tval is:"<<toStr(src)<<std::endl;
		return NULL;
	}
	SymbolRef  SEd = this->getSymbolRef(dst);
	if (!SEd){
		std::cout<<"(passTaints) getSymbolRef failed!"<<"\tval is:"<<toStr(dst)<<std::endl;
		return NULL;
	}

	ProgramStateRef newstate;

	TaintList *tlps = this->getTaintList(state,src);
	TaintList *tlpd = this->getTaintList(state,dst);
	if (!tlps){
		std::cout<<"(passTaint), no original taints return state"<<std::endl;
		return state;
	}

	// if dst symol has no taintList, just pass the src taintList
	if (!tlpd){
		newstate = this->addTaints(state, SEd, *tlps);
		std::cout<<"(passTaint) pass taints  from: "<<toStr(src)<<"\tto:\t"<<toStr(dst)<<std::endl;
		std::cout<<"src taintList is: "<<std::endl;
		tlps->showTaints("src");
	}
	//otherwise, merge the taintLists of src and dst
	else{
		//TaintList
		TaintList * m = TaintList::merge(tlps, tlpd);
		newstate = this->addTaints(state, SEd, *m);

		std::cout<<"(passTaint) pass taints  from: "<<toStr(src)<<"\tto:\t"<<toStr(dst)<<std::endl;
		std::cout<<"src taintList is: "<<std::endl;
		tlps->showTaints("src");
		std::cout<<"dst taintList is: "<<std::endl;
		tlpd->showTaints("dst");
		std::cout<<"merged taintList is: "<<std::endl;
		m->showTaints("m");
	}
	return newstate;
}

std::string DoubleFetchChecker::toStr(const Stmt* s) const{
	std::string str;
	llvm::raw_string_ostream rso(str);
	s->dump(rso);
	return rso.str();
}

std::string DoubleFetchChecker::toStr(const SVal &val) const{
	std::string str;
	llvm::raw_string_ostream rso(str);
	//std::cout << "toStr 1" << std::endl;
	val.dumpToStream(rso);
	//std::cout << "toStr 2" << std::endl;
	return rso.str();
}



unsigned int DoubleFetchChecker::getNewTag() const{
	return (unsigned int) (MaxTag + 1);
}

void DoubleFetchChecker::showTaintTags(ProgramStateRef state, SVal val) const{

	if (MaxTag == -1)
		std::cout<<"(showTaintTags), val is:"<<toStr(val)<<"\tno taint tag "<<std::endl;
	else{

		TaintList* tl = this->getTaintList(state, val);
		if(tl)
			tl->showTaints("showTaintTags");
		else
			std::cout<<"(showTaintTags) get taintList failed!"<<std::endl;

	}
}

bool DoubleFetchChecker::beTainted(ProgramStateRef state, SVal val) const{
	if (MaxTag == -1)
		return false;
	else{
		SymbolRef sr = this->getSymbolRef(val);
		if (!sr){
			std::cout<<"(beTainted) getSymbolRef failed!"<<"\tval is:"<<toStr(val)<<std::endl;
			return NULL;
		}
		return this->ifTainted(state, sr);

	}

}
//both the branch and the arg are tainted, and by different taints
//if TaintList - Branch != Empty or BranchTaint - List != Empty     then return true
//This function can be further accelerated.
bool DoubleFetchChecker::diffTaintInBranch(ProgramStateRef state, SVal arg) const{
	assert(ifTainted(state, arg));
	std::cout<<"(isInTaintedBranch)"<< "\t arg = "<<toStr(arg)<<std::endl;

	TaintList * tl = this->getTaintList(state,arg);

	BranchTaintSetTy BT = state->get<BranchTaintSet>();
	BranchTaintSetTy::iterator I, E;
	std::list<TAINT>::iterator j;

	tl->showTaints("diffTaintInBranch");

	for (I = BT.begin(), E = BT.end(); I != E; ++I) {
		for (j = tl->tlist.begin(); j!= tl->tlist.end(); j++){
			std::cout<<"(diff taint) branch taint: "<<(*I).tag<<"  val taint:"<<(*j).tag<<"\torigin:" <<toStr((*j).origin)<<std::endl;
			if (((*I).tag != (*j).tag)  &&  ((*I).origin == (*j).origin)){
				return true;
			}
		}
	}
	return false;
}


ProgramStateRef DoubleFetchChecker::addTaints(ProgramStateRef state, SymbolRef Sym, TaintList tl) const{
	// If this is a symbol cast, remove the cast before adding the taint. Taint
	// is cast agnostic.


	assert(!tl.isEmpty());
	while (const SymbolCast *SC = dyn_cast<SymbolCast>(Sym))
	     Sym = SC->getOperand();

	ProgramStateRef NewState = state->set<TaintsMap>(Sym, tl);
	assert(NewState);
	return NewState;


}

 TaintList* DoubleFetchChecker::getTaintList(ProgramStateRef state, SymbolRef Sym) const {
   if (!Sym)
     return NULL;

   TaintList * total = NULL;
   for (SymExpr::symbol_iterator SI = Sym->symbol_begin(), SE =Sym->symbol_end();
        SI != SE; ++SI) {
     if (!isa<SymbolData>(*SI))
       continue;


     const TaintList *TL = state->get<TaintsMap>(*SI);
     TaintList* temp = TaintList::unConst(TL);

     TaintList * ptr1;
     TaintList * ptr2;
     TaintList * ptr3;

	 // If this is a SymbolDerived with a tainted parent, it's also tainted.
	 if (const SymbolDerived *SD = dyn_cast<SymbolDerived>(*SI)){
		ptr1 = getTaintList(state, SD->getParentSymbol());
		temp = TaintList::merge(temp, ptr1);
	 }
	 // If memory region is tainted, data is also tainted.
	 if (const SymbolRegionValue *SRV = dyn_cast<SymbolRegionValue>(*SI)){
		 ptr2 = getTaintList(state, SRV->getRegion());
		 temp = TaintList::merge(temp, ptr2);
	 }
	 // If this is a SymbolCast from a tainted value, it's also tainted.
	 if (const SymbolCast *SC = dyn_cast<SymbolCast>(*SI)){
		 ptr3 = getTaintList(state, SC->getOperand());
		 temp = TaintList::merge(temp, ptr3);
	 }

   	 total = TaintList::merge(total, temp);
   }
   return total;
}


 TaintList* DoubleFetchChecker::getTaintList(ProgramStateRef state, const Stmt *S, const LocationContext *LCtx
                              ) const {
   if (const Expr *E = dyn_cast_or_null<Expr>(S))
     S = E->IgnoreParens();

   SVal val = state->getSVal(S, LCtx);
   return getTaintList(state, val);
 }

 TaintList* DoubleFetchChecker::getTaintList(ProgramStateRef state, SVal V) const {
   if (const SymExpr *Sym = V.getAsSymExpr())
     return getTaintList(state, Sym);
   if (const MemRegion *Reg = V.getAsRegion())
     return getTaintList(state, Reg);
   return NULL;
 }

 TaintList* DoubleFetchChecker::getTaintList(ProgramStateRef state, const MemRegion *Reg) const {
   if (!Reg)
     return NULL;

  // Element region (array element) is tainted if either the base or the offset
   // are tainted.
   if (const ElementRegion *ER = dyn_cast<ElementRegion>(Reg)){
	    TaintList* tl = getTaintList(state, ER->getSuperRegion());
	    TaintList* ts = getTaintList(state, ER->getIndex());
	   return TaintList::merge(tl, ts);
   }
   if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(Reg))
     return getTaintList(state, SR->getSymbol());

   if (const SubRegion *ER = dyn_cast<SubRegion>(Reg))
     return getTaintList(state, ER->getSuperRegion());

   return NULL;
}

bool DoubleFetchChecker::ifTainted(ProgramStateRef state, SymbolRef Sym) const {
   if (!Sym)
     return false;

   // Traverse all the symbols this symbol depends on to see if any are tainted.
   bool Tainted = false;
   for (SymExpr::symbol_iterator SI = Sym->symbol_begin(), SE =Sym->symbol_end();
        SI != SE; ++SI) {
     if (!isa<SymbolData>(*SI))
       continue;

     const TaintList *TL = state->get<TaintsMap>(*SI);
     Tainted = (TL && !TL->isEmpty());

     // If this is a SymbolDerived with a tainted parent, it's also tainted.
     if (const SymbolDerived *SD = dyn_cast<SymbolDerived>(*SI))
       Tainted = Tainted || ifTainted(state, SD->getParentSymbol());

     // If memory region is tainted, data is also tainted.
     if (const SymbolRegionValue *SRV = dyn_cast<SymbolRegionValue>(*SI))
       Tainted = Tainted || ifTainted(state, SRV->getRegion());

     // If this is a SymbolCast from a tainted value, it's also tainted.
     if (const SymbolCast *SC = dyn_cast<SymbolCast>(*SI))
       Tainted = Tainted || ifTainted(state, SC->getOperand());

     if (Tainted)
       return true;
   }

   return Tainted;
}
bool DoubleFetchChecker::ifTainted(ProgramStateRef state, const Stmt *S, const LocationContext *LCtx
                              ) const {
   if (const Expr *E = dyn_cast_or_null<Expr>(S))
     S = E->IgnoreParens();

   SVal val = state->getSVal(S, LCtx);
   return ifTainted(state, val);
 }

bool DoubleFetchChecker::ifTainted(ProgramStateRef state, SVal V) const {
   if (const SymExpr *Sym = V.getAsSymExpr())
     return ifTainted(state, Sym);
   if (const MemRegion *Reg = V.getAsRegion())
     return ifTainted(state, Reg);
   return false;
 }

bool DoubleFetchChecker::ifTainted(ProgramStateRef state, const MemRegion *Reg) const {
   if (!Reg)
     return false;

  // Element region (array element) is tainted if either the base or the offset
   // are tainted.
   if (const ElementRegion *ER = dyn_cast<ElementRegion>(Reg))
     return ifTainted(state, ER->getSuperRegion()) || ifTainted(state, ER->getIndex());

   if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(Reg))
     return ifTainted(state, SR->getSymbol());

   if (const SubRegion *ER = dyn_cast<SubRegion>(Reg))
     return ifTainted(state, ER->getSuperRegion());

   return false;
}
// registration code
void ento::registerDoubleFetchChecker(CheckerManager &mgr) {
mgr.registerChecker<DoubleFetchChecker>();
}

