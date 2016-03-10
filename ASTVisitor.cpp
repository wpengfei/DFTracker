#include <cstdio>
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <utility>
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetOptions.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Parse/ParseAST.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Rewrite/Frontend/Rewriters.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/raw_ostream.h"
using namespace clang;
using namespace std;
class MyASTVisitor : public RecursiveASTVisitor<MyASTVisitor>
{
public:
	bool VisitStmt(Stmt *s) {
		// Print name of sub‐class of s
		printf("\t%s \n", s‐>getStmtClassName() );
		return true;
		}
		bool VisitFunctionDecl(FunctionDecl *f) {
		// Print function name
		printf("%s\n", f‐>getName());
		return true;
	}
};
class MyASTConsumer : public ASTConsumer
{
public:
	MyASTConsumer()
	: Visitor() //initialize MyASTVisitor
	{}
	virtual bool HandleTopLevelDecl(DeclGroupRef DR) {
	for (DeclGroupRef::iterator b = DR.begin(), e = DR.end(); b != e; ++b) {
		// Travel each function declaration using MyASTVisitor
		Visitor.TraverseDecl(*b);
	}
	return true;
	}
private:
	MyASTVisitor Visitor;
};
int main(int argc, char *argv[])
{
		if (argc != 2) {
			llvm::errs() << "Usage: PrintFunctions <filename>\n";
			return 1;
		}
		// CompilerInstance will hold the instance of the Clang compiler for us,
		// managing the various objects needed to run the compiler.
		CompilerInstance TheCompInst;
		// Diagnostics manage problems and issues in compile
		TheCompInst.createDiagnostics(NULL, false);
		// Set target platform options
		// Initialize target info with the default triple for our platform.
		TargetOptions *TO = new TargetOptions();
		TO‐>Triple = llvm::sys::getDefaultTargetTriple();
		TargetInfo *TI = TargetInfo::CreateTargetInfo(TheCompInst.getDiagnostics(), TO);
		TheCompInst.setTarget(TI);
		// FileManager supports for file system lookup, file system caching, and directory search management.
		TheCompInst.createFileManager();
		FileManager &FileMgr = TheCompInst.getFileManager();
		// SourceManager handles loading and caching of source files into memory.
		TheCompInst.createSourceManager(FileMgr);
		SourceManager &SourceMgr = TheCompInst.getSourceManager();
		// Prreprocessor runs within a single source file
		TheCompInst.createPreprocessor();
		// ASTContext holds long‐lived AST nodes (such as types and decls) .
		TheCompInst.createASTContext();
		// A Rewriter helps us manage the code rewriting task.
		Rewriter TheRewriter;
		TheRewriter.setSourceMgr(SourceMgr, TheCompInst.getLangOpts());
		// Set the main file handled by the source manager to the input file.
		const FileEntry *FileIn = FileMgr.getFile(argv[1]);
		SourceMgr.createMainFileID(FileIn);
		// Inform Diagnostics that processing of a source file is beginning.
		TheCompInst.getDiagnosticClient().BeginSourceFile(TheCompInst.getLangOpts(),&TheCompInst.getPreprocessor());
		// Create an AST consumer instance which is going to get called by ParseAST.
		MyASTConsumer TheConsumer;
		// Parse the file to AST, registering our consumer as the AST consumer.
		ParseAST(TheCompInst.getPreprocessor(), &TheConsumer, TheCompInst.getASTContext());
		return 0;
}

