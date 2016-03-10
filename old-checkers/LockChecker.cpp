//============================================================================
// Name        : LockChecker.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

#define DOUBLELOCK 0
#define DOUBLEUNLOCK 1
#define UNRELEASELOCK 2
//
REGISTER_TRAIT_WITH_PROGRAMSTATE(LockState, bool)

class LockChecker : public Checker<check::PreCall,
								   check::EndFunction > {
	//define the bug types
	std::unique_ptr<BugType> doubleLockType;a
	std::unique_ptr<BugType> doubleUnlockType;
	std::unique_ptr<BugType> unreleasedLockType;

	public:
	  LockChecker(void);
	  void checkPreCall(const CallEvent &call, CheckerContext &C) const;
	  void checkEndFunction(CheckerContext &C) const;
	  void reportBug(CheckerContext &C,int bugType) const;

};

//----------------------------------------------------------------------------------

LockChecker::LockChecker(){
	doubleLockType.reset(
	      new BugType(this, "Double Lock", "Unix thread API Error"));
	doubleUnlockType.reset(
	      new BugType(this, "Double unlock", "Unix thread API Error"));
	unreleasedLockType.reset(
		  new BugType(this, "Unreleased lock", "Unix thread API Error"));
}

void LockChecker::reportBug(CheckerContext &C,
		int bugType)const{

	ExplodedNode *ErrNode = C.generateErrorNode();
	if (!ErrNode)
		std::cerr<<"Generate ErrNode failed.";
	    return;
	switch(bugType){
		case DOUBLELOCK :{
			auto R = llvm::make_unique<BugReport>(*doubleLockType, "Call to lock when already locked", ErrNode);
			//R->addRange(Call.getSourceRange());
			//R->markInteresting(FileDescSym);
			C.emitReport(std::move(R));
			break;
		}
		case DOUBLEUNLOCK :{
			auto R = llvm::make_unique<BugReport>(*doubleUnlockType, "Call to unlock when already unlocked", ErrNode);
			C.emitReport(std::move(R));
			break;
		}
		case UNRELEASELOCK :{
			auto R = llvm::make_unique<BugReport>(*unreleasedLockType, "Forget unlock when function finishes", ErrNode);
			C.emitReport(std::move(R));
			break;
		}
		default:{
			assert(false);
			break;
		}
	}
}

void LockChecker::checkPreCall(const CallEvent & call, CheckerContext &C) const {
  const IdentifierInfo * identInfo = call.getCalleeIdentifier();
  if(!identInfo) {
    return;
  }
  std::string funcName = std::string(identInfo->getName());
  ProgramStateRef state = C.getState();

  if(funcName.compare("pthread_mutex_lock") == 0) {
    bool currentlyLocked = state->get<LockState>();
      if(currentlyLocked) {
    	  //emit warning about double unlock
    	  this->reportBug(C, DOUBLELOCK);
      }
    state = state->set<LockState>(true);
    C.addTransition(state);
  }
  else if(funcName.compare("pthread_mutex_unlock") == 0) {
    bool currentlyLocked = state->get<LockState>();
    if(!currentlyLocked) {
      //emit warning about double unlock
    	this->reportBug(C, DOUBLEUNLOCK);
    }
    state = state->set<LockState>(false);
    C.addTransition(state);
  }
}
void LockChecker::checkEndFunction(CheckerContext &C) const {
  ProgramStateRef state = C.getState();
  bool currentlyLocked = state->get<LockState>();
  if(currentlyLocked) {
    //emit warning about returning without unlocking
	this->reportBug(C, UNRELEASELOCK);
  }
}

//register the checker
void ento::registerLockChecker(CheckerManager &mgr) {
  mgr.registerChecker<LockChecker>();
}

