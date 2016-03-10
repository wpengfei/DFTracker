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
#include <iostream>
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"



using namespace clang;
using namespace ento;
namespace {

struct LocationState {
private:
	std::string loc_str;
public:
	enum State { INI, R, W, RAR, RAW, WAR, WAW };
	mutable State S;
	LocationState(State s = INI, std::string str = "") : S(s) { loc_str  = str;}
	bool isInit() const{ return S == INI; }
	bool isFirstRead() const{ return S == R; }
	bool isFirstWrite() const{ return S == W; }
	bool isRAR() const{ return S == RAR; }
	bool isRAW() const{ return S == RAW; }
	bool isWAR() const{ return S == WAR; }
	bool isWAW() const{ return S == WAW; }
	State getCurState() const {return S;}
	//void setName(std::string str) {loc_name = str;}
	std::string getLocStr() const { return loc_str; }
	void setState(State s) const {S = s;}

	static LocationState getNewState(State s, std::string str) {
		return LocationState(s, str);
	}
	bool operator == ( const LocationState &s) const{
		if ((S == s.S) && (loc_str == s.getLocStr())){
			return true;
		}
		else
			return false;
	}
	void operator = ( const LocationState &s) {
	  S = s.S;
	  loc_str = s.getLocStr();
	}

	void Profile(llvm::FoldingSetNodeID &ID) const {
		ID.AddInteger(S);
		ID.AddString(loc_str);
	}
};

class DoubleFetchChecker : public Checker<check::Location,
										check::Bind,
										check::PreCall,
										check::PostCall,
										check::PostStmt<Expr>,
										check::PreStmt<Expr>,
										check::PreStmt<CallExpr>,
										check::PostStmt<CallExpr>,
										check::BranchCondition,
										check::EndFunction,
										check::ASTDecl<FunctionDecl> > {
private:
	std::unique_ptr<BugType> DoubleFetchType;
	static const TaintTagType TaintTagWrite = 1;
	static const TaintTagType TaintTagRead = 2;
	mutable int MaxTag = -1;// -1 indicates no tainting
	mutable std::string funcName ="";
	mutable std::string funcArg ="";
	mutable std::string funcRet = "";

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


	// my own functions
	void reportDoubleFetch(CheckerContext &Ctx) const;
	std::string toStr(SVal val) const;
	ProgramStateRef runStateMachine(const MemRegion* mrptr, SVal loc, bool isLoad, ProgramStateRef state) const ;
	unsigned int getNewTag() const;
	void showTaintTags(ProgramStateRef state, SVal val) const;
	unsigned int getCurTag(ProgramStateRef state, SVal val) const;
	bool isUntainted(ProgramStateRef state, SVal val) const;
	bool inTaintedBranch(ProgramStateRef state) const;
	bool diffTaintInBranch(ProgramStateRef state, SVal arg) const;
	ProgramStateRef addTaintTag(ProgramStateRef state, SVal val, unsigned int count) const;
	ProgramStateRef addNewTaint(ProgramStateRef state, SVal val) const;
	ProgramStateRef passTaint(ProgramStateRef state, SVal src, SVal dst) const;


}; //class end
}// namespace end



REGISTER_TRAIT_WITH_PROGRAMSTATE(TaintTag, unsigned)
//REGISTER_LIST_WITH_PROGRAMSTATE	(AccessList, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(AccessTable, const MemRegion *, LocationState) // name, key, value
REGISTER_SET_WITH_PROGRAMSTATE(BranchTaintingState, unsigned int)

DoubleFetchChecker::DoubleFetchChecker() {
	// Initialize the bug types.
	DoubleFetchType.reset(new BugType(this, "Double Fetch", "Unix kernel TOCTOU Error"));
	// Sinks are higher importance bugs as well as calls to assert() or exit(0).
	//DoubleFetchType->setSuppressOnSink(true);
}

void DoubleFetchChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	funcName = D->getNameAsString();
	funcRet = D->getReturnType().getAsString();
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

void DoubleFetchChecker::checkPreStmt(const Expr *E, CheckerContext &Ctx) const {
	//printf("check prestmt expr\n");
	ProgramStateRef state = Ctx.getState();
	SVal ExpVal = state->getSVal(E->IgnoreParens(), Ctx.getLocationContext());
	if (ExpVal.isUnknownOrUndef())
	  return;

	if(!isUntainted(state,ExpVal)){
		std::cout<<"[checkPreStmt<Expr>]"<<"\tArg0, tainted, \t ";
		showTaintTags(state, ExpVal);
	}
	 else
		std::cout<<"[checkPreStmt<Expr>] not tainted"<<"\t Expr Sval is:"<<toStr(ExpVal)<<std::endl;

}
void DoubleFetchChecker::checkPostStmt(const Expr *E, CheckerContext &Ctx) const {

	ProgramStateRef state = Ctx.getState();
	/*	SVal ExpVal = state->getSVal(E->IgnoreParens(), Ctx.getLocationContext());
	if(state->isTainted(E, Ctx.getLocationContext())){
		std::cout<<"[checkPostStmt<Expr>] state is tainted"<<std::endl;
	}
	else
		std::cout<<"[checkPreStmt<Expr>] state not tainted"<<std::endl;
	if(state->isTainted(ExpVal)){
		std::cout<<"[checkPostStmt<Expr>][taint], Sval is tainted"<<std::endl;
	}
*/

}

void DoubleFetchChecker::checkPreStmt(const CallExpr *CE, CheckerContext &Ctx) const{
/*	ProgramStateRef state = Ctx.getState();
	const FunctionDecl *FDecl = Ctx.getCalleeDecl(CE);

	if (!FDecl || FDecl->getKind() != Decl::Function)
		return;
	StringRef funcName = Ctx.getCalleeName(FDecl);

	if (funcName.empty())
		return;
	if (funcName == "kernel_func"){
		const Expr* arg = CE->getArg(0);
		if (arg->isLValue())
			printf("is lvalue\n");
		if (arg->isRValue())
			printf("is rvalue\n");

		SVal args = state->getSVal(arg->IgnoreParens(), Ctx.getLocationContext());

		const MemRegion* mr = args.getAsRegion();
		SVal val= state->getSVal(mr);

		ProgramStateRef newstate = addTaintToSymExpr(state, val);
		if (newstate){
			Ctx.addTransition(newstate);
			std::cout<<"[checkPreStmt<CallExpr>][addTaint finish]"<<"\tkernel_func: "<<toStr(args)<<std::endl;

		}
		else
			std::cout<<"[checkPreStmt<CallExpr>][addTaint failed]"<<"\tkernel_func: "<<toStr(args)<<std::endl;

	}
*/
}

void DoubleFetchChecker::checkPostStmt(const CallExpr *CE, CheckerContext &Ctx) const{
/*	ProgramStateRef state = Ctx.getState();
	const FunctionDecl *FDecl = Ctx.getCalleeDecl(CE);

	if (!FDecl || FDecl->getKind() != Decl::Function)
		return;
	StringRef funcName = Ctx.getCalleeName(FDecl);

	if (funcName.empty())
		return;
	if (funcName == "malloc"){

		const Expr* arg = CE->getArg(0);
		SVal args = state->getSVal(arg, Ctx.getLocationContext());
		if (state->isTainted(args) ){
			std::cout<<"[checkPostStmt<CallExpr>][arg Tainted]"<<"\tmallc"<<"\targ Expr: "<<toStr(args)<<std::endl;
			//add taint to return
			ProgramStateRef newstate = state->addTaint(CE, Ctx.getLocationContext());
			if (newstate!=state){
				Ctx.addTransition(newstate);
				std::cout<<"[checkPostStmt<CallExpr>][add ret Taint finish]"<<std::endl;
			}
			else
				std::cout<<"[checkPostStmt<CallExpr>][add ret Taint failed]"<<std::endl;
		}
		else
			std::cout<<"[checkPostStmt<CallExpr>][arg UnTaint]"<<"\tmallc"<<"\targ Expr"<<std::endl;

	}*/
}



void DoubleFetchChecker::checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();
	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		printf(" R return \n");
		return;
	}


	if(!isUntainted(state,val)){
		std::cout<<"[checkbind()][tainted]"<<"\tlocation is: "<<toStr(loc)<<"\tbind value is: "<<toStr(val)<<std::endl;
		showTaintTags(state, val);
	}
	else
		std::cout<<"[checkbind()][not tainted]"<<"\tlocation is: "<<toStr(loc)<<"\tbind value is: "<<toStr(val)<<std::endl;


}
ProgramStateRef DoubleFetchChecker::runStateMachine(const MemRegion* mrptr, SVal loc, bool isLoad, ProgramStateRef state) const {

	const LocationState *lptr = state->get<AccessTable>(mrptr);

	if(lptr != NULL){// recorded before
		LocationState::State s = lptr->getCurState();
		if (isLoad){
			switch (s){
				case LocationState::INI :{
					lptr->setState(LocationState::R);
					std::cout<<"\t[INI --> R]"<<std::endl;
					break;
				}
				case LocationState::R :{
					std::cout<<"\t[R --> RAR]"<<std::endl;
					lptr->setState(LocationState::RAR);
					break;
				}
				case LocationState::RAW :{
					std::cout<<"\t[RAW --> RAR]"<<std::endl;
					lptr->setState(LocationState::RAR);
					break;
				}
				case LocationState::RAR :{
					std::cout<<"\t[RAR --> RAR]"<<std::endl;
					lptr->setState(LocationState::RAR);
					break;
				}
				case LocationState::W :{
					std::cout<<"\t[ W --> RAW]"<<std::endl;
					lptr->setState(LocationState::RAW);
					break;
				}
				case LocationState::WAR :{
					std::cout<<"\t[WAR --> RAW]"<<std::endl;
					lptr->setState(LocationState::RAW);
					break;
				}
				case LocationState::WAW :{
					std::cout<<"\t[WAW --> RAW]"<<std::endl;
					lptr->setState(LocationState::RAW);
					break;
				}
				default:
					assert(false);
			}
		}
		else{
			switch (s){
				case LocationState::INI :{
					std::cout<<"\t[INI --> W]"<<std::endl;
					lptr->setState(LocationState::W);
					break;
				}
				case LocationState::R :{
					std::cout<<"\t[R --> WAR]"<<std::endl;
					lptr->setState(LocationState::WAR);
					break;
				}
				case LocationState::RAR :{
					std::cout<<"\t[RAR --> WAR]"<<std::endl;
					lptr->setState(LocationState::WAR);
					break;
				}
				case LocationState::RAW :{
					std::cout<<"\t[RAW --> WAR]"<<std::endl;
					lptr->setState(LocationState::WAR);
					break;
				}
				case LocationState::W :{
					std::cout<<"\t[W --> WAW]"<<std::endl;
					lptr->setState(LocationState::WAW);
					break;
				}
				case LocationState::WAR :{
					std::cout<<"\t[WAR --> WAW]"<<std::endl;
					lptr->setState(LocationState::WAW);
					break;
				}
				case LocationState::WAW :{
					std::cout<<"\t[WAW --> WAW]"<<std::endl;
					lptr->setState(LocationState::WAW);
					break;
				}
				default:
					assert(false);
			}
		}
		//construct new state
		state = state->set<AccessTable>(mrptr, LocationState::getNewState(lptr->getCurState(),toStr(loc)));
	}
	else{
		if (isLoad){
			state = state->set<AccessTable>(mrptr, LocationState::getNewState(LocationState::R,toStr(loc)));
			std::cout<<"\t[INI --> R]"<<std::endl;
		}
		else{
			state = state->set<AccessTable>(mrptr, LocationState::getNewState(LocationState::W,toStr(loc)));
			std::cout<<"\t[INI --> W]"<<std::endl;
		}
	}
	return state;
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

	if(!isUntainted(state, val) && isLoad)
		std::cout<<" \ttainted";
	if(isUntainted(state, val) && isLoad)
		std::cout<<" \tuntainted";

	state = runStateMachine(mrptr, loc, isLoad, state);
	Ctx.addTransition(state);

	showTaintTags(state, val);

	//any access to the user passed arg, or subregion of that arg shouled be added a new taint.
	std::string locStr = mrptr->getString();
	if (locStr == funcArg){
		std::cout<<"[checkLocation()]"<<" ==== find function decl Arg: "<<locStr<<std::endl;

		state = addNewTaint(state, val);

		Ctx.addTransition(state);
		showTaintTags(state, val);
			//std::cout<<"[checkLocation]"<<"add taint finished"<<std::endl;
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


	if(isUntainted(state, condiSval))
		std::cout<<"[checkBranch][Tainted]"<<"\tVall is"<<toStr(condiSval)<<std::endl;
	else
		std::cout<<"[checkBranch][UnTaint]"<<"\tVal is"<<toStr(condiSval)<<std::endl;
	*/


	//state->dump();
	//state->dumpTaint();

	SVal Val;
	if (const BinaryOperator *B = dyn_cast<BinaryOperator>(Condition)) {
	    if (B->isComparisonOp()) {
	    	Expr * rp = B->getRHS();
	    	Expr * lp = B->getLHS();

	    	SVal rsval = state->getSVal(rp, Ctx.getLocationContext());
	    	SVal lsval = state->getSVal(lp, Ctx.getLocationContext());

	    	if(!isUntainted(state,rsval)){
	    		std::cout<<"[checkBranch]"<<"\ttainted, binary rsval is, \t ";
	    		showTaintTags(state, rsval);
	    		unsigned int tag = this->getCurTag(state, rsval);
	    		state = state->add<BranchTaintingState>(tag);
	    		Ctx.addTransition(state);
	    	}
	    	 else
	    		std::cout<<"[checkBranch] not tainted"<<"\tbinary rsval is:"<<toStr(rsval)<<std::endl;

	    	if(!isUntainted(state,lsval)){
				std::cout<<"[checkBranch]"<<"\ttainted, binary lsval is,  \t ";
				showTaintTags(state, lsval);
				unsigned int tag = this->getCurTag(state, lsval);
				state = state->add<BranchTaintingState>(tag);
				Ctx.addTransition(state);
			}
			 else
				std::cout<<"[checkBranch] not tainted"<<"\tbinary lsval is:"<<toStr(lsval)<<std::endl;

	    }
	  }
	else if (const UnaryOperator *U = dyn_cast<UnaryOperator>(Condition)){
		Expr* sp = U->getSubExpr();
		SVal ssval = state->getSVal(sp, Ctx.getLocationContext());

		if(!isUntainted(state,ssval)){
			std::cout<<"[checkBranch]"<<"\ttainted, unary ssval is, \t ";
			showTaintTags(state, ssval);
			unsigned int tag = this->getCurTag(state, ssval);
			state = state->add<BranchTaintingState>(tag);
			Ctx.addTransition(state);
		}
		 else
			std::cout<<"[checkBranch] not tainted"<<"\tunary ssval is:"<<toStr(ssval)<<std::endl;

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

	if (ID->getName() == "__builtin___memcpy_chk") {
		SVal Arg0 = Call.getArgSVal(0);
		SVal Arg1 = Call.getArgSVal(1);
		SVal Arg2 = Call.getArgSVal(2);
		if(!isUntainted(state,Arg0)){
			std::cout<<"[checkPreCall]"<<"\tArg0, tainted, \t ";
			showTaintTags(state, Arg0);
		}
		else
			std::cout<<"[checkPreCall]"<<"\tArg0, not tainted, \t "<<std::endl;

		if(!isUntainted(state,Arg1)){
			std::cout<<"[checkPreCall]"<<"\tArg1, tainted, \t ";
			showTaintTags(state, Arg1);
		}
		else
			std::cout<<"[checkPreCall]"<<"\tArg1, not tainted, \t "<<std::endl;

		if(!isUntainted(state,Arg2)){
			std::cout<<"[checkPreCall]"<<"\tArg2, tainted, \t ";
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
void DoubleFetchChecker::checkPostCall(const CallEvent &Call,CheckerContext &Ctx) const {
	const IdentifierInfo *ID = Call.getCalleeIdentifier();
	ProgramStateRef state = Ctx.getState();
	if(ID == NULL) {
		return;
	}


	if (ID->getName() == "malloc") {
		SVal arg = Call.getArgSVal(0);
		SVal ret = Call.getReturnValue();
		if (!isUntainted(state, arg)){
			std::cout<<"[checkPostCall] arg of malloc is tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
			//pass current taint tag to retval
			ProgramStateRef newstate = passTaint(state, arg, ret);
			if (newstate!=state && newstate != NULL){
				Ctx.addTransition(newstate);
				std::cout<<"[checkPostCall][add ret Taint finish] ret is "<<toStr(ret)<<std::endl;
			}
			else
				std::cout<<"[checkPostCall][add ret Taint failed] ret is "<<toStr(ret)<<std::endl;
		}


		else{
			std::cout<<"[checkPostCall] arg of malloc not tainted."<<"\targ is:"<<toStr(arg)<<std::endl;
		}
	}

	if (ID->getName() == "malloc") {

		SVal ret = Call.getReturnValue();
		state = Ctx.getState();
		showTaintTags(state, ret);
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



ProgramStateRef DoubleFetchChecker::addTaintTag(ProgramStateRef state, SVal val, unsigned int count) const {

	if(val.isConstant()){
		std::cout<<"[addTaintToSymExpr] val failed! IsConstant."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	if(val.isUnknownOrUndef()){
		std::cout<<"[addTaintToSymExpr] val failed! IsUnknownOrUndef."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}

	const SymExpr * SE = val.getAsSymbolicExpression () ;
	if (!SE){
		std::cout<<"[addTaintToSymExpr] getAsSymbolicExpression failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	else{
		if(count > MaxTag){
			MaxTag = count;
		}
		state = state->addTaint(SE, count);
		std::cout<<"[addTaintToSymExpr] add taint finished!"<<"\tval is:"<<toStr(val)<<std::endl;
		return state;
	}
}

//any access to the user passed arg, or subregion of that arg shouled be added a new taint.
ProgramStateRef DoubleFetchChecker::addNewTaint(ProgramStateRef state, SVal val) const {
	if(val.isConstant()){
		std::cout<<"[addNewTaint] val failed! IsConstant."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	if(val.isUnknownOrUndef()){
		std::cout<<"[addNewTaint] val failed! IsUnknownOrUndef."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}

	const SymExpr * SE = val.getAsSymbolicExpression () ;
	if (!SE){
		std::cout<<"[addNewTaint] getAsSymbolicExpression failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	else{
		unsigned int newtag = getNewTag();
		MaxTag = newtag;
		ProgramStateRef newstate = state->addTaint(SE, newtag);
		std::cout<<"[addNewTaint] add new taint finished!"<<"\tval is:"<<toStr(val)<<"\t tag is:"<<newtag<<std::endl;
		if (newstate == state)
			printf("add new taint failed!\n");
		return newstate;
	}
}
//Bigger taint tag will overwrite the smaller one
ProgramStateRef DoubleFetchChecker::passTaint(ProgramStateRef state, SVal src, SVal dst) const {
	if(dst.isConstant()){
		std::cout<<"[passTaint] val failed! IsConstant."<<"\tdst is:"<<toStr(dst)<<std::endl;
		return NULL;
	}
	if(dst.isUnknownOrUndef()){
		std::cout<<"[passTaint] val failed! IsUnknownOrUndef."<<"\tdst is:"<<toStr(dst)<<std::endl;
		return NULL;
	}

	const SymExpr * SE = dst.getAsSymbolicExpression () ;
	if (!SE){
		std::cout<<"[passTaint] getAsSymbolicExpression failed!"<<"\tdst is:"<<toStr(dst)<<std::endl;
		return NULL;
	}
	else{
		for (unsigned int i = 0; i <= MaxTag; i++){
			if (state->isTainted(src, i)){
				state = state->addTaint(SE, i);
				std::cout<<"[passTaint] pass taint tag "<<i<<" from: "<<toStr(src)<<"\tto:\t"<<toStr(dst)<<std::endl;
			}
		}
		return state;
	}
}



std::string DoubleFetchChecker::toStr(const SVal &val) const{
	std::string str;
	llvm::raw_string_ostream rso(str);
	std::cout << "toStr 1" << std::endl;
	val.dumpToStream(rso);
	std::cout << "toStr 2" << std::endl;
	return rso.str();
}



unsigned int DoubleFetchChecker::getNewTag() const{
	return (unsigned int) (MaxTag + 1);
}

void DoubleFetchChecker::showTaintTags(ProgramStateRef state, SVal val) const{

	if (MaxTag == -1)
		std::cout<<"[showTaintTags], val is:"<<toStr(val)<<"\tno taint tag "<<std::endl;
	else{
		unsigned int i = 0;
		while( i <= MaxTag){
			if(state->isTainted(val, i))
				std::cout<<"[showTaintTags], val is:"<<toStr(val)<<"\t tag is: "<<i<<std::endl;
			i = i + 1;
		}
	}
}

unsigned int DoubleFetchChecker::getCurTag(ProgramStateRef state, SVal val) const{
	assert(MaxTag >= 0);
	unsigned int ret = 0;
	unsigned int i = 0;
	while( i <= MaxTag){
		if(state->isTainted(val, i)){
			//std::cout<<"[getCurTag], val is:"<<toStr(val)<<"\t tag is: "<<i<<std::endl;
			ret = i;
		}
		i = i + 1;
	}
	return ret;
}

bool DoubleFetchChecker::isUntainted(ProgramStateRef state, SVal val) const{
	if (MaxTag == -1)
		return true;
	else{
		unsigned int i = 0;
		bool ret = true;
		while (i <= MaxTag){
			if(state->isTainted(val, i)){
				ret = false;
				break;
			}
			i++;
		}
		return ret;
	}
}
// both the branch and the arg are tainted, and by different taints
bool DoubleFetchChecker::diffTaintInBranch(ProgramStateRef state, SVal arg) const{
	BranchTaintingStateTy BT = state->get<BranchTaintingState>();
	bool ret = false;
	unsigned int argtag= this->getCurTag(state, arg);
	for (BranchTaintingStateTy::iterator I = BT.begin(), E = BT.end(); I != E; ++I) {
		std::cout<<"[isInTaintedBranch]"<<"branch taint tags: "<<*I<< "\t arg = "<<toStr(arg)<<"\t argtag = "<<argtag<<std::endl;
		//the branch is controlled by more taints
		if(*I != argtag){
			ret = true;
			break;
		}
	}
	return ret;
}
// registration code
void ento::registerDoubleFetchChecker(CheckerManager &mgr) {
mgr.registerChecker<DoubleFetchChecker>();
}

