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


/* a global BranchList struct
 * which records all the branches information of the whole program.
 * It includs:
 * (1) the branch condition, which used to detemine whether this branch is taint control,
 * (2) the start and end position of all the if and else stmts, which are used to
 * decide whether a stmt is currently within a specific branch.
 */

 BranchList GlobalBranchList;
 FuncTable GlobalFuncTable;

class MyASTVisitor: public RecursiveASTVisitor<MyASTVisitor> {

private:
	SourceManager &sm;
public:
	explicit MyASTVisitor(AnalysisManager &Mgr) : sm(Mgr.getSourceManager()){}

	bool VisitStmt(Stmt* I){
		if(isa<CallExpr>(I) ){
			const CallExpr * ce = dyn_cast<CallExpr>(I);
			unsigned int loc = sm.getExpansionLineNumber(ce->getLocStart());
			std::string name = ce->getDirectCallee()->getNameAsString();
			std::cout<<"visit stmt: funcname: "<<name<<"\tloc: "<<loc<<std::endl;
			GlobalFuncTable.insertItem(loc, name);
			//GlobalFuncTable.showLoc(loc);

		}
		//if(isa<IfStmt>(I))
			//printf("is IfStmt\n");
		return true;
	}

	bool VisitIfStmt(const IfStmt *I) {
		/*collecting all the branch infomation
		 * including the branch condition and branch start/end position
		 * Each struct BRANCH stores the info for a single branch
		 */

		Expr *cond = (Expr *)I->getCond();
		const Stmt *Stmt1 = I->getThen();
		const Stmt *Stmt2 = I->getElse();

		BRANCH B;
		B.setCond(cond);
		B.condLoc = sm.getExpansionLineNumber(cond->getExprLoc());
		if (Stmt1){
			const CompoundStmt *CS1 = dyn_cast<CompoundStmt>(Stmt1);
			if (CS1){
				/*branch that has a compound,
				 * the result of which is very accurate*/
				B.ifStart = sm.getExpansionLineNumber(CS1->getLBracLoc());
				B.ifEnd = sm.getExpansionLineNumber(CS1->getRBracLoc());
			}
			else{
				/*branch that does not have a compound,
				 * the result of which is less accurate*/
				B.ifStart = sm.getExpansionLineNumber(Stmt1->getLocStart());
				B.ifEnd = sm.getExpansionLineNumber(Stmt1->getLocEnd());
			}
		}
		if (Stmt2){
			B.hasElse = true;
			const CompoundStmt *CS2 = dyn_cast<CompoundStmt>(Stmt2);
			if (CS2){
				//printf("-------->else with compound\n");
				B.elseStart = sm.getExpansionLineNumber(CS2->getLBracLoc());
				B.elseEnd = sm.getExpansionLineNumber(CS2->getRBracLoc());
			}
			else{
				//printf("-------->else without compound\n");
				B.elseStart = sm.getExpansionLineNumber(Stmt2->getLocStart());
				B.elseEnd = sm.getExpansionLineNumber(Stmt2->getLocEnd());
			}
		}
		else{
			/* If no ELSE branch is found, then we assume a virtual ELSE is there,
			 * which start from the end of IF branch to the end of this function.
			 * This assumption is for dealing with the following case
			 * if( len < buffsize)
			 * 		return;
			 * Also, chances are that false positives might be introduced.
			 */
			B.hasElse = true;

				B.elseStart = B.ifEnd +1;
				B.elseEnd = 4096;

		}

		//B.printBranch();
		std::cout<<"## AST Visitor ShowBranch ## "<<std::endl;
		B.printBranch("---> ");
		GlobalBranchList.Add(B);
		//GlobalBranchList.showBranchList("--->");
		return true;
	}

	bool VisitDecl(Decl* D){
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

	mutable unsigned int MaxTaint = 0;// 0 indicates no tainting
	mutable std::string funcName ="";
	mutable std::string funcArg ="";
	mutable std::string funcRet = "";
	mutable const FunctionDecl* funcDecl;
	mutable ArgsList AL;

public:
	DoubleFetchChecker();
	void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
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
	    MyASTVisitor Visitor(Mgr);
	    Visitor.TraverseDecl(const_cast<Decl *>(D));
	    //Visitor.TraverseStmt();
	    //Visitor.Visit(D->getBody());
	  }


	// my own functions
	void reportDoubleFetch(CheckerContext &Ctx, ProgramStateRef state) const;

	ProgramStateRef increTime(ProgramStateRef state) const; //increase the timestamp and return the new state
	unsigned int getNewTaint() const; //get new taint number
	unsigned int getCurTime(ProgramStateRef state) const;
	SymbolRef getSymbolRef(SVal val) const;
	SymbolRef getSymbolRef(const MemRegion *mr) const;


	void showValTaints(ProgramStateRef state, SVal val, std::string str) const;
	void showLocationMap(ProgramStateRef state, std::string str)const;

	bool diffTaintInBranch(ProgramStateRef state, SVal expr, const Stmt* LoadS, SourceManager &mgr) const;


	ProgramStateRef addNewTaint(ProgramStateRef state, SVal val, SVal origin) const;
	ProgramStateRef passTaints(ProgramStateRef state, SVal src, SVal dst) const;
	ProgramStateRef passTaintsToBranch(ProgramStateRef state, SVal src, const Expr *exp) const;
	//ProgramStateRef PassTaintsToLocal(ProgramStateRef state, SVal loc, TaintList &tl)const;
	ProgramStateRef addTaints(ProgramStateRef state, SymbolRef Sym, TaintList tl) const;
	ProgramStateRef addTaints(ProgramStateRef state, const MemRegion *mr, TaintList tl) const;
	ProgramStateRef addTaintToBranch(ProgramStateRef state, TAINT t)const;

	bool isLocTainted(ProgramStateRef state, SVal loc) const;
	bool isValTainted(ProgramStateRef state, SVal val) const;
	bool ifTainted(ProgramStateRef state, SymbolRef Sym) const;
	bool ifTainted(ProgramStateRef state, const Stmt *S, const LocationContext *LCtx) const;
	bool ifTainted(ProgramStateRef state, SVal V) const;
	bool ifTainted(ProgramStateRef state, const MemRegion *Reg) const;

	/* these funcs work before a specific time point,
	 *  check before time or return taintList before time */
	bool isTaintedByTime(ProgramStateRef state, SVal val)const;
	TAINT* getSingleTaintByTime(ProgramStateRef state, SVal val, unsigned int time)const;
	bool getSingleTaintListByTime(TaintList &tl, ProgramStateRef state, SVal val)const;
	void showTaintByTime(ProgramStateRef state, SVal val, std::string str)const;


	TaintList* getTaintList(ProgramStateRef state, SymbolRef Sym) const;
	TaintList* getTaintList(ProgramStateRef state, const Stmt *S, const LocationContext *LCtx) const;
	TaintList* getTaintList(ProgramStateRef state, SVal val) const;
	TaintList* getTaintList(ProgramStateRef state, const MemRegion *Reg) const;

}; //class end
}// namespace end

REGISTER_TRAIT_WITH_PROGRAMSTATE(Timer, unsigned int)
REGISTER_SET_WITH_PROGRAMSTATE(GlobalBranches, BranchList)
REGISTER_MAP_WITH_PROGRAMSTATE(TaintsMap, SymbolRef, TaintList)

/* Record the last time when a taint is added to a local var
 * indexed by a SymbolRef, has to be SymbolRef */
REGISTER_MAP_WITH_PROGRAMSTATE(LocalVarAccessRecord, SymbolRef, unsigned int)

DoubleFetchChecker::DoubleFetchChecker(){
	// Initialize the bug types.
	DoubleFetchType.reset(new BugType(this, "Double Fetch", "Unix kernel TOCTOU Error"));
	// Sinks are higher importance bugs as well as calls to assert() or exit(0).
	DoubleFetchType->setSuppressOnSink(true);
	this->MaxTaint = 0;
}

void DoubleFetchChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	std::string func =  D->getNameAsString();
	std::string arg;
	bool isPtr;
	int argNum = D->getNumParams();
	for (int i = 0; i < argNum; i++ ){
		arg = D->parameters()[i]->getQualifiedNameAsString();
		if(D->parameters()[i]->getType()->isPointerType())
			isPtr = true;
		else
			isPtr = false;

		ARG a(func, arg, isPtr);
		this->AL.Add(a);
		std::cout<<"===> checkASTDecl <=== funcName:"<<func<<"\targName:"<<arg<<"\tisPtr:"<<isPtr<<std::endl;
	}
	//funcRet = D->getReturnType().getAsString();
	//Stmt* body = D->getBody();
}



void DoubleFetchChecker::checkPreStmt(const Expr* E, CheckerContext &Ctx) const {
	ProgramStateRef state = Ctx.getState();
	SVal ExpVal = state->getSVal(E, Ctx.getLocationContext());

	SourceLocation L = E->getExprLoc();



}

void DoubleFetchChecker::checkPostStmt(const Expr* E, CheckerContext &Ctx) const {

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

}

void DoubleFetchChecker::checkPostStmt(const CallExpr *CE, CheckerContext &Ctx) const{
	ProgramStateRef state = Ctx.getState();
	const FunctionDecl *FDecl = Ctx.getCalleeDecl(CE);
	StringRef funcName = Ctx.getCalleeName(FDecl);

	/*
	  	  	const Expr * arg0 = CE->getArg(0);
			std::cout<<"[checkPostStmt]--->arg0: "<<toStr(arg0)<<std::endl;
			SourceLocation Loc0 = arg0->getExprLoc();
			StringRef name0 = Ctx.getMacroNameOrSpelling(Loc0);
			std::cout<<"[checkPostStmt]---> arg0Namen: "<<name0.str()<<std::endl;
	 */

}

void DoubleFetchChecker::checkLocation( SVal loc, bool isLoad, const Stmt* LoadS,
	CheckerContext &Ctx) const{

	std::cout<<"\n";

	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();

	unsigned int bloc = Ctx.getSourceManager().getExpansionLineNumber(LoadS->getLocEnd());
	std::cout<<"[checkLocation] location: "<<bloc<<std::endl;

	if(funcName == "copy_from_user" || funcName == "get_user")
		return;


	ProgramStateRef state = Ctx.getState();

	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		std::cout<<"[checkLocation] get MemRegion failed!\n";
		return;
	}

	std::string locStr = mrptr->getString();
	SVal val= state->getSVal(mrptr);


	unsigned int curTime = this->getCurTime(state);
	bool isTainted;


	std::cout<<"[checkLocation()]"<<" funcName is: "<<funcName<<std::endl;
	std::cout<<"[checkLocation()]"<<"\tlocation is: "<<toStr(loc)<<"\taccess value is: "<<toStr(val)<<"\t time is:"<<curTime<<std::endl;



	if (isLoad){
		/* pass loc to this func, then convert as loc->memregion->val*/
		if(this->isTaintedByTime(state, val)){
			std::cout<<"[checkLocation()] val tainted"<<std::endl;
			isTainted = true;
		}
		else{
			std::cout<<"[checkLocation()] val untainted, return"<<std::endl;
			isTainted = false;
			return;
		}
		/* pass val to this func, no convertion from loc to val*/
		this->showValTaints(state, val, "------>all taints");

	}
	else{
		std::cout<<"[checkLocation()]"<<" write neglect...return\n";
		return;
	}


	this->showLocationMap(state, "--->");

	if(isTainted ){
		/*if(AL.contains(locStr,funcName)){
			std::cout<<"[checkLocation()] is accessing base region"<<std::endl;

		}else{
			std::cout<<"[checkLocation()] is dereference"<<std::endl;
		}*/

		if(diffTaintInBranch(state,val,LoadS,Ctx.getSourceManager())){
			//unsigned int loc = Ctx.getSourceManager().getExpansionLineNumber(LoadS->getLocStart());
			//std::cout<<"------> stmtloc is: "<<loc<<std::endl;
			std::cout << "### Found DF1!!#####\n";
			//ExplodedNode *Node = Ctx.addTransition(state);
			this->reportDoubleFetch(Ctx, state);
		}



	}

}

void DoubleFetchChecker::checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();
	std::cout<<"\n";

	unsigned int bloc = Ctx.getSourceManager().getExpansionLineNumber(StoreE->getLocEnd());
	std::cout<<"[checkBind] location: "<<bloc<<std::endl;

	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();



	std::cout<<"[checkbind()]"<<" funcName is: "<<funcName<<std::endl;
	if(isValTainted(state,val)){
		std::cout<<"[checkbind()] tainted"<<"\tlocation is: "<<toStr(loc)<<"\tbind value is: "<<toStr(val)<<std::endl;
		unsigned int curTime = this->getCurTime(state);
		TaintList *tl = this->getTaintList(state, val);
		if(tl != NULL)
			tl->showTaints("--->");

		/* it is the value in loc that should be reference*/
		SymbolRef sr  = this->getSymbolRef(val);
		if (!sr){
			std::cout<<"[checkbind()]  SymbolRef failed!\n";
			return;
		}

		/*update locationMap.
		 * LocationMap, records when each local var is created.
		 */
		state = state->set<LocalVarAccessRecord>(sr,curTime);
		std::cout<<"--->add loc to LocalVarAccessRecord: SymbolRef is: "<<toStr(sr)<<"\t time is:"<<curTime<<std::endl;

		/*update timer of the checker, only when taint is passed to another expr */
		state = this->increTime(state);
		/*update program state*/
		Ctx.addTransition(state);

	}
	else
		std::cout<<"[checkbind()] untainted"<<"\tlocation is: "<<toStr(loc)<<"\tbind value is: "<<toStr(val)<<std::endl;






}
void DoubleFetchChecker::checkBranchCondition(const Stmt *Condition,
	CheckerContext &Ctx) const {

	std::cout<<"\n";
	unsigned int bloc = Ctx.getSourceManager().getExpansionLineNumber(Condition->getLocEnd());
	std::cout<<"[checkBranch] location: "<<bloc<<std::endl;
	ProgramStateRef state = Ctx.getState();

	SVal Val;
	const Expr *exp =  dyn_cast<Expr>(Condition);
	//if is binary branchCondition
	if (const BinaryOperator *B = dyn_cast<BinaryOperator>(Condition)) {
	    if (B->isComparisonOp()) {
	    	Expr * rp = B->getRHS();
	    	Expr * lp = B->getLHS();

	    	SVal rsval = state->getSVal(rp, Ctx.getLocationContext());
	    	SVal lsval = state->getSVal(lp, Ctx.getLocationContext());

	    	std::cout<<"[checkBranch]--rvalue : "<<toStr(rsval)<<std::endl;
	    	std::cout<<"[checkBranch]--lvalue : "<<toStr(lsval)<<std::endl;

	    	//std::cout<<"[checkBranch]--rvalue expr: \n"<<toStr(rp);
	    	//std::cout<<"[checkBranch]--lvalue expr: \n"<<toStr(lp);

	    	/*use isValTainted instead of isTaintedByTime(),
	    	 * because we need to pass all the taints to the branch,
	    	 * in the form of taintList
	    	 */
	    	std::cout<<"[checkBranch]--rvalue in binary cond\n";
	    	if(this->isTaintedByTime(state,rsval)){
	    		std::cout<<"[checkBranch]"<<"\ttainted, binary rsval is:  "<<toStr(rsval)<<std::endl;
	    		showValTaints(state, rsval, "--->rsval");
	    		state = this->passTaintsToBranch(state, rsval, exp);
	    		Ctx.addTransition(state);
	    	}
	    	 else
	    		std::cout<<"[checkBranch] not tainted"<<"\tbinary rsval is: "<<toStr(rsval)<<std::endl;

	    	std::cout<<"[checkBranch]--lvalue in binary cond\n";
	    	if(this->isTaintedByTime(state,lsval)){
				std::cout<<"[checkBranch]"<<"\ttainted, binary lsval is:  "<<toStr(lsval)<<std::endl;
				showValTaints(state, lsval, "--->lsval");
				state = this->passTaintsToBranch(state, lsval, exp);
				Ctx.addTransition(state);
			}
			 else
				std::cout<<"[checkBranch] not tainted"<<"\tbinary lsval is: "<<toStr(lsval)<<std::endl;

	    }
	}
	//if is unary branchCondition
	else if (const UnaryOperator *U = dyn_cast<UnaryOperator>(Condition)){
		Expr* sp = U->getSubExpr();
		SVal ssval = state->getSVal(sp, Ctx.getLocationContext());

		std::cout<<"[checkBranch]-- in unary cond\n";
		if(this->isTaintedByTime(state,ssval)){
			std::cout<<"[checkBranch]"<<"\ttainted, unary ssval is: ";
			showValTaints(state, ssval, "--->ssval");
			state = this->passTaintsToBranch(state, ssval, exp);
			Ctx.addTransition(state);
		}
		 else
			std::cout<<"[checkBranch] not tainted"<<"\tunary ssval is: "<<toStr(ssval)<<std::endl;

	}
	else{
		std::cout<<"[checkBranch]-- get branch failed\n";
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
	std::cout<<"\n";
	std::cout<<"[checkPreCall]-----call function:"<<ID->getName().str()<<std::endl;

}
void DoubleFetchChecker::checkPostCall(const CallEvent &Call,CheckerContext &Ctx) const {
	const IdentifierInfo *ID = Call.getCalleeIdentifier();
	std::cout<<"\n";
	std::cout<<"[checkPostCall]------call function:"<<ID->getName().str()<<std::endl;

	ProgramStateRef state = Ctx.getState();


	if(ID == NULL) {
		return;
	}
	unsigned int curTime = this->getCurTime(state);
	/*everytime copy_from_user is invoked,
	 *a new tainted is added to the taintList of the first Arg,
	 *which is the fetched value in kernel
	 */

	if (ID->getName() == "copy_from_user"){

		SVal Val0 = state->getSVal(Call.getArgExpr(0), Ctx.getLocationContext());
		SVal origin = state->getSVal(Call.getArgExpr(1), Ctx.getLocationContext());
		SVal len = state->getSVal(Call.getArgExpr(2), Ctx.getLocationContext());
		std::cout<<"[checkPostCall]---> Val0: "<<toStr(Val0)<<std::endl;
		std::cout<<"[checkPostCall]---> origin: "<<toStr(origin)<<std::endl;
		std::cout<<"[checkPostCall]---> len: "<<toStr(len)<<std::endl;
		/* here has to use val1 as the origin,
		 * since it is conveted from the actuall Expr
		 */
		state = this->addNewTaint(state, Val0, origin);

		/*after making change to time line, we need to increase the time */
		state = this->increTime(state);
		std::cout<<"[checkPostCall] timer++"<<std::endl;
		if(state != NULL)
			Ctx.addTransition(state);

	}



	if (ID->getName() == "get_user" || ID->getName() =="__get_user"){

			SVal arg0 = Call.getArgSVal(0);
			SVal arg1 = Call.getArgSVal(1);
			std::cout<<"--->arg0: "<<toStr(arg0)<<std::endl;
			std::cout<<"--->arg1: "<<toStr(arg1)<<std::endl;

			//const Expr* e0 = Call.getArgExpr(0);
			//const Expr* e1 =Call.getArgExpr(1);

			/* here has to use val1 as the origin,
			 * since it is conveted from the actuall Expr
			 */
			state = this->addNewTaint(state, arg0, arg1);

			/*after making change to time line, we need to increase the time */
			state = this->increTime(state);
			std::cout<<"[checkPostCall] timer++"<<std::endl;
			if(state != NULL)
				Ctx.addTransition(state);

	}
	if (ID->getName() == "malloc" || ID->getName() == "UserAllocPoolWithQuota") {
		int num = Call.getNumArgs();
		SVal arg = Call.getArgSVal(0);
		SVal ret = Call.getReturnValue();
		/*no need to check by time*/
		if (this->isValTainted(state, arg)){
			std::cout<<"[checkPostCall] arg of malloc is tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
			//pass current taint taint to return value
			ProgramStateRef newstate = passTaints(state, arg, ret);
			if (newstate!=state && newstate != NULL){
				Ctx.addTransition(newstate);
				std::cout<<"[checkPostCall]add ret Taint finish, ret is: "<<toStr(ret)<<std::endl;
				showValTaints(newstate, ret, "--->ret: ");
			}
			else
				std::cout<<"[checkPostCall] add ret Taint failed,  ret is "<<toStr(ret)<<std::endl;
		}

		else{
			std::cout<<"[checkPostCall] arg of malloc not tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
		}
	}
	//int num = Call.getNumArgs();
	//for(int i =0; i< num; i++){
	if (ID->getName() == "CMSG_COMPAT_ALIGN") {
			SVal arg = Call.getArgSVal(0);
			SVal ret = Call.getReturnValue();
			/*no need to check by time*/
			if (this->isValTainted(state, arg)){
				std::cout<<"[checkPostCall] arg of anyfunc is tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
				//pass current taint taint to return value
				ProgramStateRef newstate = passTaints(state, arg, ret);
				if (newstate!=state && newstate != NULL){
					Ctx.addTransition(newstate);
					std::cout<<"[checkPostCall]add ret Taint finish, ret is: "<<toStr(ret)<<std::endl;
					showValTaints(newstate, ret, "--->ret: ");
					return;
				}
				else
					std::cout<<"[checkPostCall] add ret Taint failed,  ret is "<<toStr(ret)<<std::endl;
			}

			else{
				std::cout<<"[checkPostCall] arg of anyfunc not tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
			}
	}

}


void DoubleFetchChecker::checkEndFunction(CheckerContext &Ctx) const {
	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();
	std::cout<<"[checkEndFunction]: "<<funcName<<"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;
}

ProgramStateRef DoubleFetchChecker::addNewTaint(ProgramStateRef state, SVal val, SVal origin) const {
	SymbolRef  sr = this->getSymbolRef(val);
	if (!sr){
		std::cout<<"--->(addNewTaint) getSymbolRef failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	else{



	unsigned int curTime = this->getCurTime(state);
	SVal val;
		unsigned int newtaint = this->getNewTaint();
		ProgramStateRef newstate;
		const TaintList *tlp = state->get<TaintsMap>(sr);
		//tainted before, just add new taint to the taintList
		if (tlp){
			tlp->Add(newtaint, origin, curTime);
			newstate = this->addTaints(state, sr, *tlp);
			std::cout<<"--->(addNewTaint) tainted before, just add new taint to the taintList!\n";
			tlp->showTaints("------>");
		}
		//not tainted before, add a new taintList to the symbol
		else{
			TaintList tl(newtaint, origin, curTime);
			newstate = this->addTaints(state, sr, tl);
			std::cout<<"--->(addNewTaint) not tainted before, add a new taintList to the symbol!\n";
			tl.showTaints("------>");
		}

		std::cout<<"--->(addNewTaint) add new taint finished!"<<"\ttainted val is:"<<toStr(val)<<"\t taint is:"<<newtaint<<"\ttime is: "<<time<<std::endl;

		return newstate;
	}
}

/*pass the taints of src to BRANCH
 * which means get the taintlist tls from src, then add it to the GlobalBranches
 */
ProgramStateRef DoubleFetchChecker::passTaintsToBranch(ProgramStateRef state, SVal src, const Expr* exp) const {


	TaintList tls;
	bool ret= this->getSingleTaintListByTime(tls, state, src);
	if (!ret){
		std::cout<<"--->(passTaintToBranch), no original taints return state"<<std::endl;
		return state;
	}

	tls.showTaints("--->(pass taint to branch):src taints:");


	GlobalBranchesTy GB = state->get<GlobalBranches>();
	GlobalBranchesTy::iterator I = GB.begin();
	GlobalBranchesTy::iterator E = GB.end();


	/* empty at beginning, then at the GlobalBranchList to it */
	if (I == E){
		std::cout<<"--->(passTaintToBranch), no previous branchList, add a new one to branch: v"<<std::endl;

		GlobalBranchList.addTaintsToSpecBranch(exp, tls);
		state = state->add<GlobalBranches>(GlobalBranchList);
		GlobalBranchList.showBranchList("--->");
	}
	else{
		std::cout<<"--->(passTaintToBranch), has branchList: v"<<std::endl;

		(*I).addTaintsToSpecBranch(exp, tls);
		state = state->remove<GlobalBranches>(*I);
		state = state->add<GlobalBranches>(*I);
		(*I).showBranchList("--->");
	}

	return state;
}
/*pass taints from Expr src to Expr dst,
 * in the form of taintList,
 * just the newest taint before time,
 */
ProgramStateRef DoubleFetchChecker::passTaints(ProgramStateRef state, SVal src, SVal dst) const {


	std::cout<<"--->(passTaint) pass taints from: "<<toStr(src)<<"\tto:\t"<<toStr(dst)<<std::endl;
	SymbolRef  sr_src = this->getSymbolRef(src) ;
	if (!sr_src){
		std::cout<<"--->(passTaints) getSymbolRef failed!"<<"\tval is:"<<toStr(src)<<std::endl;
		return NULL;
	}
	SymbolRef  sr_dst = this->getSymbolRef(dst);
	if (!sr_dst){
		std::cout<<"--->(passTaints) getSymbolRef failed!"<<"\tval is:"<<toStr(dst)<<std::endl;
		return NULL;
	}

	unsigned int time = this->getCurTime(state);

	TaintList tld;
	TaintList tls;



	/*get the newest taint before 'time'
	 * in the form of taintList : tld, tks
	 */
	bool retd = this->getSingleTaintListByTime(tld, state, dst);
	bool rets = this->getSingleTaintListByTime(tls, state, src);

	if (!rets){
		std::cout<<"--->(passTaint), get taintList from src failed, src is empty."<<std::endl;
		return state;
	}

	/* if dst symol has no taintList, just pass the src taintList */
	if (!retd){
		state = this->addTaints(state, sr_dst, tls);
		std::cout<<"--->(passTaint) pass taints finished. dst is empty"<<std::endl;

	}
	/*otherwise, merge the taintLists of src and dst*/
	else{
		TaintList * m = TaintList::merge(&tls, &tld);
		state = this->addTaints(state, sr_src, *m);

		std::cout<<"---> (passTaint) timer++"<<std::endl;
		state = this->increTime(state);

		std::cout<<"--->(passTaint) pass taints finished"<<std::endl;
	}
	return state;
}



bool DoubleFetchChecker::diffTaintInBranch(ProgramStateRef state, SVal val, const Stmt* LoadS, SourceManager &mgr) const{
	//assert(ifTainted(state, arg));
	TaintList tl;

	std::list<TAINT>::iterator i, j;
	GlobalBranchesTy GB = state->get<GlobalBranches>();
	GlobalBranchesTy::iterator I, E;
	I = GB.begin();
	E = GB.end();
	/*Get the GlobalBranch list,
	 * which should be pointed by  iterator I.
	 */
	if(I != E){

		/*get the taints of val, stored in tl*/
		bool ret = this->getSingleTaintListByTime(tl, state, val);
		if(ret)
			tl.showTaints("--->(diffTaintInBranch)-val: ");

		/* check if Expr (in the form of loc) within a controlled branch,
		 * return the taintlist of that branch, stored in btl.
		 * otherwise return null
		 * LoadS is Expr*/
		unsigned int location = mgr.getExpansionLineNumber(LoadS->getLocStart());

		if( GlobalFuncTable.getNameByLoc(location) == "get_user"){
			std::cout<<"--->(it is source func, return)\n";
			return false;
		}

		std::cout<<"--->(diffTaintInBranch) location: "<<location<<std::endl;
		TaintList * btl = (*I).getBranchTLbyExprLoc(location);

		if ( btl != NULL){

			if(btl->isEmpty())
				std::cout<<"--->(get empty)\n";
			btl->showTaints("--->(diffTaintInBranch)-branch: ");
			for (i = tl.getList().begin(); i != tl.getList().end(); i++) {
					for (j = btl->getList().begin(); j!= btl->getList().end(); j++){
						if (((*i).taint != (*j).taint)  &&  ((*i).origin == (*j).origin)){
							printf("DDDDDDDDFFFFFF!!!!!!!!!!!!!!!!!!!!!!!!\n");
							return true;
						}
					}
			}
		}
		else
			std::cout<<"--->(diffTaintInBranch) : get controlled branch taintlist failed.\n";

	}
	else
		std::cout<<"--->(diffTaintInBranch) : get GlobalBranchesTy failed, probably no branch yet.\n";

	return false;
}


void DoubleFetchChecker::showValTaints(ProgramStateRef state, SVal val, std::string str = "") const{

	if (MaxTaint == 0)
		std::cout<<str<<"(showValTaints), val is:"<<toStr(val)<<"\tno taints "<<std::endl;
	else{
		TaintList* tl = this->getTaintList(state, val);
		if(tl)
			tl->showTaints(str);
		else
			std::cout<<str<<"(showValTaints) get taintList failed!"<<std::endl;

	}
}

/*both the branch and the arg are tainted, and by different taints
 *if TaintList - Branch != Empty or BranchTaint - List != Empty     then return true
 *This function can be further accelerated.
 */
void DoubleFetchChecker::showTaintByTime(ProgramStateRef state, SVal val, std::string str = "")const{
		if (MaxTaint == 0){
			std::cout<<str<<"(showTaintByTime) no taint!"<<std::endl;
			return;
		}
		std::cout<<str<<"(showTaintByTime) val:"<<toStr(val)<<std::endl;


		SymbolRef sr = this->getSymbolRef(val);
		if(!sr)
			std::cout<<str<<"(showTaintByTime) get symbolref failed!"<<std::endl;

		const unsigned int * timep = state->get<LocalVarAccessRecord>(sr);
		if(!timep){
			std::cout<<str<<"(showTaintByTime) get<LocalVarAccessRecord> failed\n";
			unsigned int curTime = this->getCurTime(state);
			TAINT* tp = this->getSingleTaintByTime(state, val, curTime);
			if(tp)
				tp->showTaint(str+"(showTaintByTime)->curTime->showTaint");
			return;
		}
		else{
			TAINT* tp = this->getSingleTaintByTime(state, val, *timep);
			if(tp)
				tp->showTaint(str+"(showTaintByTime)->LocationMapTime->showTaint");
			return;
		}
}
void DoubleFetchChecker::showLocationMap(ProgramStateRef state, std::string str = "")const{
	LocalVarAccessRecordTy LM = state->get<LocalVarAccessRecord>();
	LocalVarAccessRecordTy::iterator I = LM.begin();
	LocalVarAccessRecordTy::iterator E = LM.end();

	for(I = LM.begin(); I != E; I++){
		std::cout<<str<<"(showLocationMap)"<<"\tloc: "<<toStr((*I).first)<<"\ttime: "<<(*I).second<<std::endl;
	}

}

TAINT* DoubleFetchChecker::getSingleTaintByTime(ProgramStateRef state, SVal val, unsigned int time)const{
	TaintList *tlps = this->getTaintList(state, val);
	if(!tlps)
		return NULL;
	return tlps->getTaintByTime(time);
}

SymbolRef DoubleFetchChecker::getSymbolRef(SVal val) const {
	if(val.isConstant()){
		std::cout<<"--->(getSymbolRef) failed! IsConstant."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	if(val.isUnknownOrUndef()){
		std::cout<<"--->(getSymbolRef) failed! IsUnknownOrUndef."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	const SymExpr * SE = val.getAsSymExpr();
	if (SE != NULL){
		//std::cout<<"--->(getSymbolRef) getAsSymExpr succeed!"<<std::endl;
		return SE;
	}
	else{
		//std::cout<<"--->(getSymbolRef) getAsSymExpr failed!, try get memregion"<<"\tval is:"<<toStr(val)<<std::endl;
		const MemRegion *Reg = val.getAsRegion();
		if(!Reg){
			std::cout<<"--->(getSymbolRef) getAsRegion failed!"<<"\tval is:"<<toStr(val)<<std::endl;
			return NULL;
		}
		else{
			if (const SymbolicRegion *SR = dyn_cast_or_null<SymbolicRegion>(Reg)){
				//std::cout<<"--->(getSymbolRef) getAsRegion succeed."<<std::endl;
				return SR->getSymbol();
			}
			else{
				std::cout<<"--->(getSymbolRef) memRegion get symbolref failed."<<std::endl;
				return NULL;
			}


		}
	}

}
bool DoubleFetchChecker::getSingleTaintListByTime(TaintList &tl, ProgramStateRef state, SVal val)const{

	SymbolRef sr  = this->getSymbolRef(val);

	if (!sr){
		std::cout<<"[getSingleTaintListByTime] get SymbolRef failed!\n";
		return false;
	}
/*
	const MemRegion *mr = loc.getAsRegion();
	if (!mr){
		std::cout<<"--->(getSingleTaintListByTime) get MemRegion failed, return!, loc is: "<<toStr(loc)<<std::endl;
		return false;
	}
	SVal val= state->getSVal(mr);
*/
	TAINT *T = NULL;
	unsigned int t;
	/*this region is a region that taint is passed from somewhere else*/
	const unsigned int * timep = state->get<LocalVarAccessRecord>(sr);
	if(timep != NULL){
		t = *timep;
		std::cout<<"--->(getSingleTaintListByTime) get<LocalVarAccessRecord> succeed, time = "<<t<<std::endl;
	}
	/*this region is a region that taint is added originally*/
	else{
		t = this->getCurTime(state);
		std::cout<<"--->(getSingleTaintListByTime) get<LocalVarAccessRecord> failed, curtime= "<<t<<std::endl;
	}

	/*get the newest taint before 'time'*/
	T = this->getSingleTaintByTime(state, val, t);
	if(!T){
		std::cout<<"--->(getSingleTaintListByTime) getSingleTaintByTime failed"<<std::endl;
		return false;
	}
	T->showTaint("--->(getSingleTaintListByTime) newest taint: ");

	/*store the new taint to tl */
	tl.Add(*T);
	tl.showTaints("------>(getSingleTaintListByTime)--return taintList with new taint: ");
	return true;
}
/* unused func*/
SymbolRef DoubleFetchChecker::getSymbolRef(const MemRegion *mr) const {

	if (const SymbolicRegion *SR = dyn_cast_or_null<SymbolicRegion>(mr)){
		std::cout<<"--->(getSymbolRef) memRegion get symbolref succeed."<<std::endl;
		return SR->getSymbol();
	}
	else{
		std::cout<<"--->(getSymbolRef) memRegion get symbolref failed."<<std::endl;
		return NULL;
	}

}
unsigned int DoubleFetchChecker::getCurTime(ProgramStateRef state) const{
	unsigned int t = state->get<Timer>();
	if(t)
		return t;
	else
		return 1;
}
unsigned int DoubleFetchChecker::getNewTaint() const{
	this->MaxTaint = this->MaxTaint + 1;
	return MaxTaint;
}

ProgramStateRef DoubleFetchChecker::increTime(ProgramStateRef state) const{
	unsigned int t = state->get<Timer>();
	if(t){
		state = state -> set<Timer>(t + 1);
		return state;
	}
	else{
		state = state -> set<Timer>( 2);
		return state;
	}
}


bool DoubleFetchChecker::isTaintedByTime(ProgramStateRef state, SVal val)const{
	if (MaxTaint == 0)
		return false;

	TAINT* tp;
	SymbolRef sr  = this->getSymbolRef(val);
	if (!sr){
		std::cout<<"--->(isTaintedByTime) get SymbolRef failed!\n";
		return false;
	}
/*
	const MemRegion *mr  = loc.getAsRegion();
	if (!mr){
		std::cout<<"--->get Memregion failed!\n";
		return false;
	}
	/* check taint has to check the val in that loc,
	 * checking the loc does't work */
/*	SVal val= state->getSVal(mr);
*/
	/*this region is a region that taint is passed from somewhere else*/
	const unsigned int * timep = state->get<LocalVarAccessRecord>(sr);
	if(timep != NULL){
		std::cout<<"--->(isTaintedByTime) get<LocalVarAccessRecord> succeed, is a taint from assignment\n";
		tp = this->getSingleTaintByTime(state, val, *timep);
	}
	/*this region is a region that taint is added originally*/
	else{
		std::cout<<"--->(isTaintedByTime) get<LocalVarAccessRecord> failed, is a taint added originally\n";
		unsigned int curTime = this->getCurTime(state);
		tp = this->getSingleTaintByTime(state, val, curTime);
	}
	if (tp != NULL){
		tp->showTaint("------>");
		return true;
	}
	else
		return false;
}


/*
bool DoubleFetchChecker::isLocTainted(ProgramStateRef state, SVal loc) const{
	if (MaxTaint == 0)
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
*/
bool DoubleFetchChecker::isValTainted(ProgramStateRef state, SVal val) const{
	if (MaxTaint == 0)
		return false;
	else{
		SymbolRef sr = this->getSymbolRef(val);
		if (!sr){
			std::cout<<"--->(isValTainted) getSymbolRef failed!"<<"\tval is:"<<toStr(val)<<std::endl;
			return false;
		}
		return this->ifTainted(state, sr);

	}

}

ProgramStateRef DoubleFetchChecker::addTaints(ProgramStateRef state, const MemRegion *mr, TaintList tl) const{
	SymbolRef Sym;
	if (const SymbolicRegion *SR = dyn_cast_or_null<SymbolicRegion>(mr)){
		std::cout<<"--->(addTaints) memRegion get symbolref succeed."<<std::endl;
		Sym = SR->getSymbol();
	}
	else{
		std::cout<<"--->(getSymbolRef) memRegion get symbolref failed."<<std::endl;
		return NULL;
	}

	assert(!tl.isEmpty());
	while (const SymbolCast *SC = dyn_cast<SymbolCast>(Sym))
	     Sym = SC->getOperand();

	ProgramStateRef NewState = state->set<TaintsMap>(Sym, tl);
	assert(NewState);
	return NewState;
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

void DoubleFetchChecker::reportDoubleFetch(CheckerContext &Ctx, ProgramStateRef state) const {
	// We reached a bug, stop exploring the path here by generating a sink.
	//ExplodedNode *ErrNode = Ctx.generateErrorNode(Ctx.getState());
	ExplodedNode *N = Ctx.generateNonFatalErrorNode(state);
	// If we've already reached this node on another path, return.
	if (!N)
		return;

	// Generate the report.
	auto R = llvm::make_unique<BugReport>(*DoubleFetchType,
			"DF, use of untrusted data", N);
	//R->addRange(Call.getSourceRange());
	Ctx.emitReport(std::move(R));
}

// registration code
void ento::registerDoubleFetchChecker(CheckerManager &mgr) {
	mgr.registerChecker<DoubleFetchChecker>();
}

