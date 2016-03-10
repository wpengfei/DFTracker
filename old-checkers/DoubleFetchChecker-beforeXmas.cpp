/*
 * DoubleFetchChecker.cpp
 *
 *  Created on: 2015年10月26日
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
#include "TaintStructs.h"


using namespace clang;
using namespace ento;
namespace {


// a branchList record the branches information of the whole program
BranchList GlobalBranchList;

class MyASTVisitor: public RecursiveASTVisitor<MyASTVisitor> {

	SourceManager &sm;
public:
	explicit MyASTVisitor(AnalysisManager &Mgr) : sm(Mgr.getSourceManager()){}

	bool VisitStmt(Stmt* I){
		//if(isa<CompoundStmt>(I) )
			//printf("is CompoundStmt\n");
		//if(isa<IfStmt>(I))
			//printf("is IfStmt\n");
		//printf("-------->visit stmt\n");
		return true;
	}

	bool VisitIfStmt(const IfStmt *I) {
		printf("-------->get IfStmt\n");
		Expr *cond = (Expr *)I->getCond();
		const Stmt *Stmt1 = I->getThen();
		const Stmt *Stmt2 = I->getElse();

		BRANCH B;
		B.setCond(cond);
		B.condLoc = sm.getExpansionLineNumber(cond->getExprLoc());
		if (Stmt1){
			printf("-------->if enter\n");
			const CompoundStmt *CS1 = dyn_cast<CompoundStmt>(Stmt1);
			if (CS1){
				//printf("-------->if with compound\n");
				B.ifStart = sm.getExpansionLineNumber(CS1->getLBracLoc());
				B.ifEnd = sm.getExpansionLineNumber(CS1->getRBracLoc());
				//B.ifStart = CS1->getLocStart();
				//B.ifEnd = CS1->getLocEnd();
			}
			else{
				//printf("-------->if without compound\n");
				B.ifStart = sm.getExpansionLineNumber(Stmt1->getLocStart());
				B.ifEnd = sm.getExpansionLineNumber(Stmt1->getLocEnd());
			}
		}
		if (Stmt2){
			B.hasElse = true;
			printf("-------->else enter\n");
			const CompoundStmt *CS2 = dyn_cast<CompoundStmt>(Stmt2);
			if (CS2){
				//printf("-------->else with compound\n");
				B.elseStart = sm.getExpansionLineNumber(CS2->getLBracLoc());
				B.elseEnd = sm.getExpansionLineNumber(CS2->getRBracLoc());
				//B.elseStart = CS2->getLocStart();
				//B.elseEnd = CS2->getLocEnd();
			}
			else{
				//printf("-------->else without compound\n");
				B.elseStart = sm.getExpansionLineNumber(Stmt2->getLocStart());
				B.elseEnd = sm.getExpansionLineNumber(Stmt2->getLocEnd());
			}
		}

		//B.printBranch();
		GlobalBranchList.Add(B);
		GlobalBranchList.showBranchList("begin AST");
		return true;
	}

	bool VisitDecl(Decl* D){
		printf("visit decl\n");
		return true;
	}
	bool VisitFunctionDecl(FunctionDecl *f) {

		//std::cout<<"visit funcdecl:"<<f->getNameAsString()<<std::endl;

		return true;
	}

};


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
	mutable ArgsList AL;

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
		std::cout<<"checkASTCodeBody\n";
	    MyASTVisitor Visitor(Mgr);
	    Visitor.TraverseDecl(const_cast<Decl *>(D));
	    std::cout<<"checkASTCodeBody2\n";
	    //Visitor.TraverseStmt();
	    //Visitor.Visit(D->getBody());
	  }


	// my own functions
	void reportDoubleFetch(CheckerContext &Ctx, const CallEvent &Call) const;

	unsigned int getNewTag() const;
	unsigned int getCurTime(ProgramStateRef state) const;
	ProgramStateRef getIncreTime(ProgramStateRef state) const;
	SymbolRef getSymbolRef(SVal val) const;


	void showTaintByTime(ProgramStateRef state, SVal val)const;
	void showValTaintTags(ProgramStateRef state, SVal val) const;
	void showLocationMap(ProgramStateRef state)const;
	bool diffTaintInBranch(ProgramStateRef state, SVal arg, const Expr * erg, SourceManager &mgr) const;


	ProgramStateRef addNewTaint(ProgramStateRef state, SVal val, unsigned int time) const;
	ProgramStateRef passTaints(ProgramStateRef state, SVal src, SVal dst) const;
	ProgramStateRef passTaintsToBranch(ProgramStateRef state, SVal src, const Expr *exp) const;
	ProgramStateRef PassTaintsToLocal(ProgramStateRef state, SVal loc, TaintList &tl)const;
	ProgramStateRef addTaints(ProgramStateRef state, SymbolRef Sym, TaintList tl) const;
	ProgramStateRef addTaintToBranch(ProgramStateRef state, TAINT t)const;

	bool isLocTainted(ProgramStateRef state, SVal loc) const;
	bool isValTainted(ProgramStateRef state, SVal val) const;
	bool ifTainted(ProgramStateRef state, SymbolRef Sym) const;
	bool ifTainted(ProgramStateRef state, const Stmt *S, const LocationContext *LCtx) const;
	bool ifTainted(ProgramStateRef state, SVal V) const;
	bool ifTainted(ProgramStateRef state, const MemRegion *Reg) const;

	bool isTaintedByTime(ProgramStateRef state, SVal loc)const;
	TAINT* getSingleTaintByTime(ProgramStateRef state, SVal val, unsigned int time)const;
	bool getSingleTaintListByTime(TaintList &tl, ProgramStateRef state, SVal val, unsigned int time)const;

	TaintList* getTaintList(ProgramStateRef state, SymbolRef Sym) const;
	TaintList* getTaintList(ProgramStateRef state, const Stmt *S, const LocationContext *LCtx) const;
	TaintList* getTaintList(ProgramStateRef state, SVal val) const;
	TaintList* getTaintList(ProgramStateRef state, const MemRegion *Reg) const;

}; //class end
}// namespace end

REGISTER_TRAIT_WITH_PROGRAMSTATE(Timer, unsigned int)
REGISTER_MAP_WITH_PROGRAMSTATE(LocationMap, SymbolRef, unsigned int )

REGISTER_SET_WITH_PROGRAMSTATE(GlobalBranches, BranchList)
REGISTER_MAP_WITH_PROGRAMSTATE(LocalVarMap, const MemRegion *,TaintList)
REGISTER_MAP_WITH_PROGRAMSTATE(TaintsMap, SymbolRef, TaintList)
//REGISTER_SET_WITH_PROGRAMSTATE(BranchTaintSet, TAINT)

DoubleFetchChecker::DoubleFetchChecker(){
	// Initialize the bug types.
	DoubleFetchType.reset(new BugType(this, "Double Fetch", "Unix kernel TOCTOU Error"));
	// Sinks are higher importance bugs as well as calls to assert() or exit(0).
	//DoubleFetchType->setSuppressOnSink(true);
}

void DoubleFetchChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	std::string func =  D->getNameAsString();
	std::string arg;
	int argNum = D->getNumParams();
	for (int i = 0; i < argNum; i++ ){
		arg = D->parameters()[i]->getQualifiedNameAsString();
		ARG a(func, arg);
		this->AL.Add(a);
	}
	//funcRet = D->getReturnType().getAsString();
	//Stmt* body = D->getBody();
}



void DoubleFetchChecker::checkPostStmt(const BlockExpr *BE, CheckerContext &Ctx) const{

	const BlockDecl* bd = BE->getBlockDecl();
	std::cout<<"[checkPostStmt<BlockExpr>]"<<"xxxxxxxxxxxxxxxxxxxx"<<std::endl;
}

void DoubleFetchChecker::checkPreStmt(const Expr* E, CheckerContext &Ctx) const {
	ProgramStateRef state = Ctx.getState();
	SVal ExpVal = state->getSVal(E, Ctx.getLocationContext());

	//SourceManager sm = Ctx.getSourceManager();
	SourceLocation L = E->getExprLoc();
	//std::cout<<"xxxsssssssssssssssssssssssssssssssssssssssss"<<std::endl;
	//std::cout<<"ss"<<L.printToString(Ctx.getSourceManager())<<std::endl;

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
	//if (isa<BlockExpr>(E))
		//std::cout<<"sssssssssssssssssssssssssssssssssssssssss"<<std::endl;
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
	//printf("[checkPreStmt<CallExpr>] func name is:%s\n",funcName);
	//std::cout<<"-------------------->getLocStart: "<<CE->getLocStart().getRawEncoding()<<std::endl;
	//std::cout<<"--------------------->getLocEnd: "<<CE->getLocEnd().getRawEncoding()<<std::endl;
	//std::cout<<"-------------------->getExprLoc: "<<CE->getExprLoc().getRawEncoding()<<std::endl;

	unsigned int spelling = Ctx.getSourceManager().getSpellingLineNumber(CE->getExprLoc());
	unsigned int ex = Ctx.getSourceManager().getExpansionLineNumber(CE->getExprLoc());

	//std::cout<<"spelling: "<<spelling<<"ex: "<<ex<<std::endl;
	//std::cout<<"str::"<<CE->getExprLoc().printToString(Ctx.getSourceManager())<<std::endl;
}

void DoubleFetchChecker::checkPostStmt(const CallExpr *CE, CheckerContext &Ctx) const{
	ProgramStateRef state = Ctx.getState();
	const FunctionDecl *FDecl = Ctx.getCalleeDecl(CE);
	StringRef funcName = Ctx.getCalleeName(FDecl);
	//std::cout<<"[checkPostStmt<CallExpr>] func name is:"<<funcName<<std::endl;
	//printf("[checkPostStmt<CallExpr>] func name is:%s\n",funcName);

}

ProgramStateRef DoubleFetchChecker::PassTaintsToLocal(ProgramStateRef state, SVal loc, TaintList &tl)const{
	ProgramStateRef newstate;
	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		printf(" PassTaintsToLocal R return \n");
		return NULL;
	}
	const TaintList *origin_tl = state->get<LocalVarMap>(mrptr);
	tl.showTaints("PassTaintsToLocal");
	if(!origin_tl){
		newstate = state->set<LocalVarMap>(mrptr, tl);
		std::cout<<"(PassTaintsToLocal)"<<" not original taints\n";
	}
	else{
		std::cout<<"(PassTaintsToLocal)"<<" has original taints\n";
		TaintList *origin = TaintList::unConst(origin_tl);
		TaintList *m = TaintList::merge(origin, &tl);
		newstate = state->set<LocalVarMap>(mrptr, *m);
		m->showTaints("PassTaintsToLocal--m");
	}

	return newstate;
}

void DoubleFetchChecker::checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();

	if(isValTainted(state,val)){
		std::cout<<"[checkbind()][tainted]"<<"\tlocation is: "<<toStr(loc)<<"\tbind value is: "<<toStr(val)<<std::endl;
		//
		//TaintList *tl = this->getTaintList(state, val);
		//state = PassTaintsToLocal(state, loc, *tl);
		//Ctx.addTransition(state);
		//showTaintTags(state, val);
		SymbolRef sr = this->getSymbolRef(val);
		//const MemRegion *mrptr = loc.getAsRegion();
		if (!sr){
			std::cout<<"[checkLocation] get MemRegion failed!\n";
				return;
		}
		//update timer of the checker, only when taint is passed to another expr
		unsigned int curTime = this->getCurTime(state);
		state = state -> set<Timer>(curTime);
		//update location map
		state = state->set<LocationMap>(sr,curTime);
		std::cout<<"[checkbind()]"<<"\tadd loc to record location: "<<toStr(loc)<<"\t time is:"<<curTime<<std::endl;
		//update program state
		state = this->getIncreTime(state);
		Ctx.addTransition(state);

	}
	else
		std::cout<<"[checkbind()][not tainted]"<<"\tlocation is: "<<toStr(loc)<<"\tbind value is: "<<toStr(val)<<std::endl;


}
void DoubleFetchChecker::showLocationMap(ProgramStateRef state)const{
	LocationMapTy LM = state->get<LocationMap>();
	LocationMapTy::iterator I = LM.begin();
	LocationMapTy::iterator E = LM.end();

	for(I = LM.begin(); I != E; I++){
		std::cout<<"(showLocationMap)"<<"\ttime: "<<(*I).second<<std::endl;
	}

}

unsigned int DoubleFetchChecker::getCurTime(ProgramStateRef state) const{
	unsigned int t = state->get<Timer>();
	if(t)
		return t;
	else
		return 0;
}
ProgramStateRef DoubleFetchChecker::getIncreTime(ProgramStateRef state) const{
	unsigned int t = state->get<Timer>();
	if(t){
		state = state -> set<Timer>(t + 1);
		return state;
	}
	else{
		state = state -> set<Timer>( 1);
		return state;
	}
}


void DoubleFetchChecker::checkLocation( SVal loc, bool isLoad, const Stmt* LoadS,
	CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();
	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		std::cout<<"[checkLocation] get MemRegion failed!\n";
			return;
	}


	unsigned int curTime = this->getCurTime(state);

	this->showLocationMap(state);
	SVal val= state->getSVal(mrptr);
	std::cout<<"[checkLocation()]"<<"\tlocation is: "<<toStr(loc)<<"\taccess value is: "<<toStr(val)<<"\t time is:"<<curTime;


	if (isLoad){
		//if(isLocTainted(state, loc))
			//std::cout<<" \tloc tainted"<<std::endl;
		if(isValTainted(state, val))
			std::cout<<" \tval tainted"<<std::endl;

		//if(!isLocTainted(state, loc))
			//std::cout<<" \tloc untainted"<<std::endl;
		if(!isValTainted(state, val))
			std::cout<<" \tval untainted"<<std::endl;

		this->showValTaintTags(state, val);

	}
	else
		std::cout<<"[checkLocation()]"<<" write\n";

	//taint the arg if it is recorded from  the AST
	std::string locStr = mrptr->getString();
	if(AL.contains(locStr)){
		std::cout<<"[checkLocation()]"<<" ==== find function decl Arg: "<<locStr<<std::endl;
		state = addNewTaint(state, val, curTime);
		//after making change to time line, we need to increase the time
		state = this->getIncreTime(state);
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
	const Expr *exp =  dyn_cast<Expr>(Condition);
	if (const BinaryOperator *B = dyn_cast<BinaryOperator>(Condition)) {
	    if (B->isComparisonOp()) {
	    	Expr * rp = B->getRHS();
	    	Expr * lp = B->getLHS();

	    	SVal rsval = state->getSVal(rp, Ctx.getLocationContext());
	    	SVal lsval = state->getSVal(lp, Ctx.getLocationContext());

	    	if(this->isTaintedByTime(state,rsval)){
	    		std::cout<<"[checkBranch]"<<"\ttainted, binary rsval is:  "<<toStr(rsval)<<std::endl;
	    		showValTaintTags(state, rsval);
	    		state = passTaintsToBranch(state, rsval, exp);
	    		Ctx.addTransition(state);
	    	}
	    	 else
	    		std::cout<<"[checkBranch] not tainted"<<"\tbinary rsval is: "<<toStr(rsval)<<std::endl;

	    	if(this->isTaintedByTime(state,lsval)){
				std::cout<<"[checkBranch]"<<"\ttainted, binary lsval is:  "<<toStr(lsval)<<std::endl;
				showValTaintTags(state, lsval);
				state = passTaintsToBranch(state, lsval, exp);
				Ctx.addTransition(state);
			}
			 else
				std::cout<<"[checkBranch] not tainted"<<"\tbinary lsval is: "<<toStr(lsval)<<std::endl;

	    }
	}
	else if (const UnaryOperator *U = dyn_cast<UnaryOperator>(Condition)){
		Expr* sp = U->getSubExpr();
		SVal ssval = state->getSVal(sp, Ctx.getLocationContext());

		if(this->isTaintedByTime(state,ssval)){
			std::cout<<"[checkBranch]"<<"\ttainted, unary ssval is: ";
			showValTaintTags(state, ssval);
			state = passTaintsToBranch(state, ssval, exp);
			Ctx.addTransition(state);
		}
		 else
			std::cout<<"[checkBranch] not tainted"<<"\tunary ssval is: "<<toStr(ssval)<<std::endl;

	}

	// two branches
	//ProgramStateRef trueState, falseState;
	//std::tie(trueState, falseState) = state->assume(dv);


}
void DoubleFetchChecker::showTaintByTime(ProgramStateRef state, SVal val)const{
		if (MaxTag == -1)
			std::cout<<"(showTaintByTime) no taint!"<<std::endl;
		std::cout<<"(showTaintByTime):"<<toStr(val)<<std::endl;
		SymbolRef sr = this->getSymbolRef(val);
		//const MemRegion *mrptr = loc.getAsRegion();
		if(!sr){
			std::cout<<"(showTaintByTime) getAsRegion failed!"<<std::endl;
			this->showValTaintTags(state, val);
			return;
		}
		const unsigned int * timep = state->get<LocationMap>(sr);
		if(!timep){
			std::cout<<"(showTaintByTime) get<LocationMap> failed, return from showValTaintTags()\n";
			//this->showValTaintTags(state, val);
			unsigned int curTime = this->getCurTime(state);
			TAINT* tp = this->getSingleTaintByTime(state, val, curTime);
			tp->showTaint("(showTaintByTime)->curTime->showTaint");
			return;
		}
		else{
			TAINT* tp = this->getSingleTaintByTime(state, val, *timep);
			tp->showTaint("showTaintByTime->LocationMapTime->showTaint");
			return;
		}
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


	if (ID->getName() == "__builtin___memcpy_chk") {
		SVal Arg0 = Call.getArgSVal(0);
		SVal Arg1 = Call.getArgSVal(1);
		SVal Arg2 = Call.getArgSVal(2);

		const Expr * erg0 = Call.getArgExpr(0);

		const Expr * erg1 = Call.getArgExpr(1);

		const Expr * erg2 = Call.getArgExpr(2);

		if(this->isTaintedByTime(state,Arg0)){
			std::cout<<"[checkPreCall]"<<"\tArg0, tainted, \t "<<std::endl;
			showTaintByTime(state, Arg0);

		}
		else
			std::cout<<"[checkPreCall]"<<"\tArg0, not tainted, \t "<<std::endl;

		if(this->isTaintedByTime(state,Arg1)){
			std::cout<<"[checkPreCall]"<<"\tArg1, tainted, \t "<<std::endl;
			showTaintByTime(state, Arg1);
		}
		else
			std::cout<<"[checkPreCall]"<<"\tArg1, not tainted, \t "<<std::endl;

		if(this->isTaintedByTime(state,Arg2)){
			std::cout<<"[checkPreCall]"<<"\tArg2, tainted, \t "<<std::endl;
			showTaintByTime(state, Arg2);
		}
		else
			std::cout<<"[checkPreCall]"<<"\tArg2, not tainted, \t "<<std::endl;

		if(diffTaintInBranch(state,Arg0,erg0,Ctx.getSourceManager())){
			llvm::errs() << "### Found DF1!!#####\n";
			this->reportDoubleFetch(Ctx, Call);
		}
		if(diffTaintInBranch(state,Arg1,erg1,Ctx.getSourceManager())){
			llvm::errs() << "### Found DF2!!#####\n";
			this->reportDoubleFetch(Ctx, Call);
		}
		if(diffTaintInBranch(state,Arg2,erg2, Ctx.getSourceManager())){
			llvm::errs() << "### Found DF3!!#####\n";
			this->reportDoubleFetch(Ctx, Call);

		}
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
		if (this->isTaintedByTime(state, arg)){
			std::cout<<"[checkPostCall] arg of malloc is tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
			//pass current taint tag to return value
			ProgramStateRef newstate = passTaints(state, arg, ret);
			if (newstate!=state && newstate != NULL){
				Ctx.addTransition(newstate);
				std::cout<<"[checkPostCall][add ret Taint finish] ret is "<<toStr(ret)<<std::endl;
				showValTaintTags(newstate, ret);
			}
			else
				std::cout<<"[checkPostCall][add ret Taint failed] ret is "<<toStr(ret)<<std::endl;
		}

		else{
			std::cout<<"[checkPostCall] arg of malloc not tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
		}
	}


}
void DoubleFetchChecker::reportDoubleFetch(CheckerContext &Ctx, const CallEvent &Call) const {
	// We reached a bug, stop exploring the path here by generating a sink.
	ExplodedNode *ErrNode = Ctx.generateErrorNode(Ctx.getState());
	// If we've already reached this node on another path, return.
	if (!ErrNode)
		return;

	// Generate the report.
	auto R = llvm::make_unique<BugReport>(*DoubleFetchType,
			"Double-Fetch", ErrNode);
	R->addRange(Call.getSourceRange());
	Ctx.emitReport(std::move(R));
}

void DoubleFetchChecker::checkEndFunction(CheckerContext &Ctx) const {
	std::cout<<"[checkEndFunction]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;
}

//any access to the user passed arg, or subregion of that arg shouled be added a new taint.
ProgramStateRef DoubleFetchChecker::addNewTaint(ProgramStateRef state, SVal val, unsigned int time) const {
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
			//tlp->clear();
			tlp->Add(newtag, val, time);
			newstate = addTaints(state, SE, *tlp);
			std::cout<<"(addNewTaint) tainted before, just add new tag to the taintList!\n";
		}
		//not tainted before, add a new taintList to the symbol
		else{
			TaintList tl(newtag, val, time);
			newstate = addTaints(state, SE, tl);
			std::cout<<"(addNewTaint) not tainted before, add a new taintList to the symbol!\n";
		}

		std::cout<<"(addNewTaint) add new taint finished!"<<"\tval is:"<<toStr(val)<<"\t tag is:"<<newtag<<"\ttime is: "<<time<<std::endl;
		/*if (newstate->get<TaintsMap>(SE)){
			const TaintList *s = newstate->get<TaintsMap>(SE);
			s->showTaints("add new taint succedd");
		}*/
		return newstate;
	}
}
ProgramStateRef DoubleFetchChecker::passTaintsToBranch(ProgramStateRef state, SVal src, const Expr* exp) const {


	TaintList tls;
	unsigned int time = this->getCurTime(state);
	bool ret= this->getSingleTaintListByTime(tls, state, src, time);
	if (!ret){
		std::cout<<"(passTaintToBranch), no original taints return state"<<std::endl;
		return state;
	}
	tls.showTaints("pass taint to branch");



	GlobalBranchesTy GB = state->get<GlobalBranches>();
	GlobalBranchesTy::iterator I = GB.begin();
	GlobalBranchesTy::iterator E = GB.end();


	// empty at beginning, then at the GlobalBranchList to it
	if (I == E){
		std::cout<<"(passTaintToBranch), no previous branchList"<<std::endl;

		GlobalBranchList.addTaintsToSpecBranch(exp, tls);
		state = state->add<GlobalBranches>(GlobalBranchList);
		GlobalBranchList.showBranchList();
	}
	else{
		std::cout<<"(passTaintToBranch), has branchList"<<std::endl;

		(*I).addTaintsToSpecBranch(exp, tls);
		state = state->remove<GlobalBranches>(*I);
		state = state->add<GlobalBranches>(*I);
		(*I).showBranchList();
	}

	return state;
/*
	std::list<TAINT>::iterator i;

	for ( i=tlps->getList().begin(); i!=tlps->getList().end(); i++ ) {
		std::cout<<"(passTaintsToBranch,for)\t tag: "<<(*i).tag<<"\t origin: "<<this->toStr((*i).origin)<<std::endl;

		if (state->contains<BranchTaintSet>(*i)){
			continue;
		}
		else{
			//std::cout<<"bbbbb"<<(*i).tag<<"   "<<this->toStr((*i).origin)<<std::endl;
			state = state->add<BranchTaintSet>(*i);
		}

	}
	return state;*/
}

TAINT* DoubleFetchChecker::getSingleTaintByTime(ProgramStateRef state, SVal val, unsigned int time)const{
	TaintList *tlps = this->getTaintList(state,val);
	if(!tlps)
		return NULL;
	//unsigned int time = this->getCurTime(state);
	return tlps->getTaintByTime(time);
}

bool DoubleFetchChecker::getSingleTaintListByTime(TaintList &tl, ProgramStateRef state, SVal val, unsigned int time)const{
	TaintList *tlps = this->getTaintList(state,val);
	if(!tlps)
		return false;
	//unsigned int time = this->getCurTime(state);
	std::cout<<"(getSingleTaintListByTime) time:"<<time<<std::endl;
	tlps->showTaints("getSingleTaintListByTime--before");
	TAINT *T = tlps->getTaintByTime(time);
	if(!T){
		std::cout<<"null\n";
		return false;
	}
	//T->showTaint();

	tl.Add(*T);
	tl.showTaints("getSingleTaintListByTime--after");
	return true;
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

	unsigned int time = this->getCurTime(state);
	ProgramStateRef newstate;
	TaintList tld;
	TaintList tls;

	bool retd = this->getSingleTaintListByTime(tld, state, dst, time);
	bool rets = this->getSingleTaintListByTime(tls, state, src, time);

	if (!rets){
		std::cout<<"(passTaint), get  taintList from src failed."<<std::endl;
		return state;
	}
	// if dst symol has no taintList, just pass the src taintList
	if (!retd){
		tls.showTaints("src");
		newstate = this->addTaints(state, SEd, tls);
		std::cout<<"(passTaint) pass taints  from: "<<toStr(src)<<"\tto:\t"<<toStr(dst)<<std::endl;

	}

	//otherwise, merge the taintLists of src and dst
	else{
		printf("f4\n");
		TAINT *src_taint = this->getSingleTaintByTime(state,src, time);
		if(!src_taint)
			std::cout<<"(passTaint) getSingleTaintByTime failed\n";
		src_taint->time = this->getCurTime(state);
		state = this->getIncreTime(state);
		tld.Add(*src_taint);
		//TaintList * m = TaintList::merge(tlps, tlpd);

		newstate = this->addTaints(state, SEd, tld);

		std::cout<<"(passTaint) pass taints  from: "<<toStr(src)<<"\tto:\t"<<toStr(dst)<<std::endl;

		tls.showTaints("src");

		tld.showTaints("dst");
	}
	return newstate;
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
		//return NULL;
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
void DoubleFetchChecker::showValTaintTags(ProgramStateRef state, SVal val) const{

	if (MaxTag == -1)
		std::cout<<"(showValTaintTags), val is:"<<toStr(val)<<"\tno taint tag "<<std::endl;
	else{
		//SVal val = state->getSVal(mrptr);
		TaintList* tl = this->getTaintList(state, val);
		if(tl)
			tl->showTaints("showValTaintTags");
		else
			std::cout<<"(showValTaintTags) get taintList failed!"<<std::endl;

	}
}

//both the branch and the arg are tainted, and by different taints
//if TaintList - Branch != Empty or BranchTaint - List != Empty     then return true
//This function can be further accelerated.
bool DoubleFetchChecker::diffTaintInBranch(ProgramStateRef state, SVal arg, const Expr * erg, SourceManager &mgr) const{
	assert(ifTainted(state, arg));
	std::cout<<"(isInTaintedBranch)"<< "\t arg = "<<toStr(arg)<<std::endl;

	unsigned int loc = mgr.getExpansionLineNumber(erg->getExprLoc());
	unsigned int time = this->getCurTime(state);

	//get the taint of arg, stored in tl
	TaintList tl;
	bool ret = this->getSingleTaintListByTime(tl, state,arg, time);

	std::list<TAINT>::iterator i, j;
	GlobalBranchesTy GB = state->get<GlobalBranches>();
	GlobalBranchesTy::iterator I, E;
	I = GB.begin();
	E = GB.end();
	if(I != E){
		//printf("hello\n");
		//if exp in a controlled branch, return the taintlist of that branch, otherwise return null
		TaintList * btl = (*I).exprInTaintedBranch(erg, loc);
		if (btl){
			for (i = tl.getList().begin(); i != tl.getList().end(); i++) {
					for (j = btl->getList().begin(); j!= btl->getList().end(); j++){
						std::cout<<"(diffTaintInBranch) branch taint: "<<(*i).tag<<"  val taint:"<<(*j).tag<<"\torigin:" <<toStr((*j).origin)<<std::endl;
						if (((*i).tag != (*j).tag)  &&  ((*i).origin == (*j).origin)){
							//printf("DDDDDDDDFFFFFF\n");
							return true;
						}
					}
			}
		}
		else
			std::cout<<"(diffTaintInBranch) : get controlled branch taintlist failed.\n";

	}
	else
		std::cout<<"(diffTaintInBranch) : get GlobalBranchesTy failed.\n";



	//BranchTaintSetTy BT = state->get<BranchTaintSet>();
	//BranchTaintSetTy::iterator I, E;


	tl.showTaints("No diff Taint In Branch-->>");


	return false;
}


unsigned int DoubleFetchChecker::getNewTag() const{
	return (unsigned int) (MaxTag + 1);
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

 TaintList* DoubleFetchChecker::getTaintList(ProgramStateRef state, SVal loc) const {
/*	const MemRegion *mrptr = loc.getAsRegion();
	if(!mrptr){
		printf("getTaintListp~~~~~~~0~~~~\n");
		//return NULL;
	}
	else{
		printf("getTaintListp~~~~~MemRegion succeed~~2~~~~\n");
		std::string str = mrptr->getString();
		std::cout<<"getTaintListp memregion is:"<<str<<std::endl;
		const TaintList * tl = state->get<LocalVarMap>(mrptr);
		if (tl){
			printf("get tl from localvarmap succeed~~~~~3~~~~~~\n");
			TaintList* temp = TaintList::unConst(tl);
			return temp;
		}
		else
			printf("get tl from localvarmap failed~~~~~5~~~~~~\n");
	}
*/
	if (const SymExpr *Sym = loc.getAsSymExpr())
	     return getTaintList(state, Sym);
	if (const MemRegion *Reg = loc.getAsRegion())
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
bool DoubleFetchChecker::isTaintedByTime(ProgramStateRef state, SVal val)const{
	if (MaxTag == -1)
		return false;
	std::cout<<"(isTaintedByTime): val is:"<<toStr(val)<<std::endl;
	SymbolRef sr = this->getSymbolRef(val);
	//const MemRegion *mrptr = loc.getAsRegion();
	if(!sr){
		std::cout<<"(isTaintedByTime) getAsRegion failed!return from ifTainted()"<<std::endl;
		return ifTainted(state, val);
	}
	const unsigned int * timep = state->get<LocationMap>(sr);
	if(!timep){
		std::cout<<"(isTaintedByTime) get<LocationMap> failed, return with curtime \n";
		//return ifTainted(state, val);
		unsigned int curTime = this->getCurTime(state);
		TAINT* tp = this->getSingleTaintByTime(state, val, curTime);
		tp->showTaint("(isTaintedByTime)->curTime->showTaint");
		if (tp)
			return true;
		else
			return false;
	}
	else{
		TAINT* tp = this->getSingleTaintByTime(state, val, *timep);
		tp->showTaint("(isTaintedByTime)->LocationMapTime->showTaint");
		if (tp)
			return true;
		else
			return false;
	}


}
bool DoubleFetchChecker::isLocTainted(ProgramStateRef state, SVal loc) const{
	if (MaxTag == -1)
		return false;
	else{
		const MemRegion *mrptr = loc.getAsRegion();
		if(!mrptr)
			std::cout<<"(isLocTainted) getAsRegion failed!"<<std::endl;
		const TaintList *tl = state->get<LocalVarMap>(mrptr);
		if (tl){
			return true;
		}
		return false;
	}
}

bool DoubleFetchChecker::isValTainted(ProgramStateRef state, SVal val) const{
	if (MaxTag == -1)
		return false;
	else{
		SymbolRef sr = this->getSymbolRef(val);
		if (!sr){
			std::cout<<"(isValTainted) getSymbolRef failed!"<<"\tval is:"<<toStr(val)<<std::endl;
			return false;
		}
		return this->ifTainted(state, sr);

	}

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

